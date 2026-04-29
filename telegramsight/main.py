"""Fetch vulnerability sightings from the Telegram collector and push them to
Vulnerability-Lookup. Intended to be run periodically from cron.
"""

from __future__ import annotations

import argparse
import base64
import importlib.util
import logging
import os
import re
import sys
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from types import ModuleType
from typing import Any
from urllib.parse import urlparse

import dateparser
import requests
from cryptography.hazmat.primitives.ciphers.aead import AESSIV
from pyvulnerabilitylookup import PyVulnerabilityLookup

logger = logging.getLogger("telegramsight")

CONFIG_ENV_VAR = "TeleGramSight_CONFIG"
API_PATH = "/api/get_cve_objs"
DEFAULT_PAGE_SIZE = 100
DEFAULT_WINDOW = timedelta(hours=24)

# Telegram public usernames are 5–32 chars, start with a letter, and use only
# letters/digits/underscore. Anything else in a t.me/<seg> URL — numeric ids,
# +invite hashes, /c/<id>/ permalinks — is treated as a private channel.
_PUBLIC_USERNAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{4,31}$")


def load_config() -> ModuleType:
    path = os.environ.get(CONFIG_ENV_VAR)
    if not path:
        raise RuntimeError(
            f"{CONFIG_ENV_VAR} must be set to the path of a Python config file"
        )
    spec = importlib.util.spec_from_file_location("telegramsight_config", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load config from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_aessiv(key_b64: str | None) -> AESSIV:
    if not key_b64:
        raise RuntimeError("source_encryption_key must be set in the config")
    # Accept both padded and unpadded urlsafe-base64.
    padded = key_b64 + "=" * (-len(key_b64) % 4)
    key = base64.urlsafe_b64decode(padded)
    if len(key) not in (32, 48, 64):
        raise RuntimeError(
            "source_encryption_key must decode to 32, 48, or 64 bytes "
            f"(got {len(key)})"
        )
    return AESSIV(key)


def encrypt_source_fragment(aessiv: AESSIV, chat_id: Any, msg_id: Any) -> str:
    """Deterministic AES-SIV encrypt of `{chat_id}/{msg_id}`.

    AES-SIV is used with no nonce and no associated data, so the output is
    a pure function of (key, plaintext) — the same message always produces
    the same source string, which lets Vulnerability-Lookup dedupe on the
    ciphertext without decrypting.

    Returns urlsafe-base64 of the SIV-prefixed ciphertext, padding stripped.
    """
    ciphertext = aessiv.encrypt(f"{chat_id}/{msg_id}".encode(), None)
    return base64.urlsafe_b64encode(ciphertext).decode().rstrip("=")


def sighting_type(result: dict[str, Any]) -> str:
    if result.get("tag_wildusage"):
        return "exploited"
    if result.get("tag_poc"):
        return "published-proof-of-concept"
    return "seen"


def parse_time(value: str) -> int:
    """Parse a time argument into unix-epoch seconds.

    Accepts, in order:
      - an all-digit unix-epoch seconds value,
      - an ISO 8601 timestamp,
      - a natural-language expression like "2 days ago", "yesterday", "today".
    """
    if value.isdigit():
        return int(value)
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        maybe = dateparser.parse(
            value, settings={"RETURN_AS_TIMEZONE_AWARE": True, "TIMEZONE": "UTC"}
        )
        if maybe is None:
            raise ValueError(f"Could not parse time value: {value!r}")
        parsed = maybe
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return int(parsed.timestamp())


def iter_results(
    api_url: str,
    api_key: str,
    since: int,
    until: int,
    page_size: int,
    include_msg: bool = True,
) -> Iterator[dict[str, Any]]:
    endpoint = api_url.rstrip("/") + API_PATH
    session = requests.Session()
    page = 1
    while True:
        payload = {
            "api_key": api_key,
            "from": since,
            "to": until,
            "page": page,
            "page_size": page_size,
            "msg": include_msg,
            "tag_llm": True,
        }
        response = session.post(endpoint, json=payload, timeout=30)
        response.raise_for_status()
        body = response.json()
        results = body.get("results") or []
        if not results:
            return
        yield from results
        total = int(body.get("total") or 0)
        if page * page_size >= total:
            return
        page += 1


def is_public_channel(result: dict[str, Any]) -> bool:
    """Conservative check: only return True when the channel URL points at a
    Telegram public username. Any non-username path (numeric chat_id fallback,
    `+invite_hash`, `/c/<id>/...` permalink, missing field, …) is treated as
    private — message text from such channels must never be exposed.
    """
    channel = result.get("channel")
    if not isinstance(channel, str):
        return False
    segments = [s for s in urlparse(channel).path.split("/") if s]
    if not segments:
        return False
    return bool(_PUBLIC_USERNAME_RE.match(segments[0]))


def build_sighting(
    aessiv: AESSIV, result: dict[str, Any], include_text: bool = False
) -> dict[str, Any] | None:
    vuln_id = result.get("vuln_id")
    chat_id = result.get("chat_id")
    msg_id = result.get("msg_id")
    pub_timestamp = result.get("pub_timestamp")
    if not (vuln_id and chat_id and msg_id and pub_timestamp):
        logger.debug("Skipping result with missing required fields: %s", result)
        return None
    # PyVulnerabilityLookup.create_sighting inspects .tzinfo on this value,
    # so it must be a datetime, not the ISO string the upstream API returns.
    try:
        creation_timestamp = datetime.fromisoformat(pub_timestamp)
    except ValueError:
        logger.debug(
            "Skipping result with unparseable pub_timestamp: %r", pub_timestamp
        )
        return None
    if creation_timestamp.tzinfo is None:
        creation_timestamp = creation_timestamp.replace(tzinfo=timezone.utc)
    sighting: dict[str, Any] = {
        "type": sighting_type(result),
        "vulnerability": vuln_id,
        "creation_timestamp": creation_timestamp,
    }
    # Two mutually-exclusive paths:
    #   - Public channel with a valid `username` field → canonical t.me link
    #     as the source; the message text MAY be attached as `content` if
    #     the operator opted in via `include_text`.
    #   - Anything else (private channels, public-looking URLs whose
    #     `username` field is missing or malformed, etc.) → opaque
    #     deterministic AES-SIV ciphertext as the source, and message text
    #     is NEVER attached. Keeping the `content` assignment physically
    #     inside the public branch makes that invariant structural rather
    #     than relying on a flag that could drift in a future refactor.
    username = result.get("username")
    if (
        is_public_channel(result)
        and isinstance(username, str)
        and _PUBLIC_USERNAME_RE.match(username)
    ):
        sighting["source"] = f"https://t.me/{username}/{msg_id}"
        text = result.get("text")
        if include_text and text:
            sighting["content"] = text
    else:
        sighting["source"] = (
            f"Telegram/{encrypt_source_fragment(aessiv, chat_id, msg_id)}"
        )
    return sighting


def push_sighting(client: PyVulnerabilityLookup, sighting: dict[str, Any]) -> bool:
    try:
        client.create_sighting(sighting=sighting)
    except Exception as exc:
        logger.warning("Failed to push sighting %s: %s", sighting, exc)
        return False
    return True


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="telegramsight",
        description=(
            "Fetch vulnerability sightings from the Telegram collector and push "
            "them to a Vulnerability-Lookup instance."
        ),
    )
    parser.add_argument(
        "--since",
        help=(
            "Start of the time window. Accepts unix-epoch seconds, an ISO 8601 "
            "timestamp, or a natural-language expression like '2 days ago'. "
            "Defaults to 24 hours before --until."
        ),
    )
    parser.add_argument(
        "--until",
        help=(
            "End of the time window. Accepts unix-epoch seconds, an ISO 8601 "
            "timestamp, or a natural-language expression like 'today'. "
            "Defaults to now."
        ),
    )
    parser.add_argument(
        "--page-size",
        type=int,
        default=DEFAULT_PAGE_SIZE,
        help=f"Results per API call (default: {DEFAULT_PAGE_SIZE}).",
    )
    parser.add_argument(
        "--no-push",
        action="store_true",
        help=(
            "Dry run: fetch, build, and log each sighting, but do not "
            "contact the Vulnerability-Lookup instance."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    args = build_parser().parse_args(argv)
    config = load_config()

    now = datetime.now(tz=timezone.utc)
    until = parse_time(args.until) if args.until else int(now.timestamp())
    since = (
        parse_time(args.since)
        if args.since
        else int(
            (
                datetime.fromtimestamp(until, tz=timezone.utc) - DEFAULT_WINDOW
            ).timestamp()
        )
    )
    if since >= until:
        logger.error("--since (%d) must be earlier than --until (%d)", since, until)
        return 2

    aessiv = load_aessiv(getattr(config, "source_encryption_key", None))
    include_text = bool(getattr(config, "include_text", False))
    client = (
        None
        if args.no_push
        else PyVulnerabilityLookup(
            config.vulnerability_lookup_base_url,
            token=config.vulnerability_auth_token,
        )
    )

    pushed = 0
    seen = 0
    for result in iter_results(
        config.api_url,
        config.api_key,
        since,
        until,
        args.page_size,
        getattr(config, "include_msg", True),
    ):
        seen += 1
        sighting = build_sighting(aessiv, result, include_text)
        if sighting is None:
            continue
        if client is None:
            logger.info("DRY-RUN would push: %s", sighting)
            pushed += 1
        elif push_sighting(client, sighting):
            pushed += 1

    verb = "Would push" if client is None else "Pushed"
    logger.info(
        "%s %d/%d sightings for window [%d, %d]",
        verb,
        pushed,
        seen,
        since,
        until,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
