"""Fetch vulnerability sightings from the Telegram collector and push them to
Vulnerability-Lookup. Intended to be run periodically from cron.
"""

from __future__ import annotations

import argparse
import base64
import importlib.util
import logging
import os
import sys
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from types import ModuleType
from typing import Any

import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pyvulnerabilitylookup import PyVulnerabilityLookup

logger = logging.getLogger("telegramsight")

CONFIG_ENV_VAR = "TeleGramSight_CONFIG"
API_PATH = "/api/get_cve_objs"
DEFAULT_PAGE_SIZE = 100
DEFAULT_WINDOW = timedelta(hours=24)


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


def load_aesgcm(key_b64: str | None) -> AESGCM:
    if not key_b64:
        raise RuntimeError("source_encryption_key must be set in the config")
    # Accept both padded and unpadded urlsafe-base64.
    padded = key_b64 + "=" * (-len(key_b64) % 4)
    key = base64.urlsafe_b64decode(padded)
    if len(key) != 32:
        raise RuntimeError(
            f"source_encryption_key must decode to 32 bytes (got {len(key)})"
        )
    return AESGCM(key)


def encrypt_source_fragment(aesgcm: AESGCM, chat_id: Any, msg_id: Any) -> str:
    """AES-256-GCM encrypt `{chat_id}/{msg_id}` with a fresh 12-byte nonce.

    Returns urlsafe-base64(nonce || ciphertext || tag), padding stripped.
    """
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, f"{chat_id}/{msg_id}".encode(), None)
    return base64.urlsafe_b64encode(nonce + ciphertext).decode().rstrip("=")


def sighting_type(result: dict[str, Any]) -> str:
    if result.get("tag_poc"):
        return "proof_of_concept"
    if result.get("tag_wildusage"):
        return "exploited"
    return "seen"


def parse_time(value: str) -> int:
    """Accept either unix-epoch seconds or an ISO 8601 timestamp; return epoch seconds."""
    if value.isdigit():
        return int(value)
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return int(parsed.timestamp())


def iter_results(
    api_url: str,
    api_key: str,
    since: int,
    until: int,
    page_size: int,
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
            "msg": True,
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


def build_sighting(
    aesgcm: AESGCM, result: dict[str, Any]
) -> dict[str, Any] | None:
    vuln_id = result.get("vuln_id")
    chat_id = result.get("chat_id")
    msg_id = result.get("msg_id")
    pub_timestamp = result.get("pub_timestamp")
    if not (vuln_id and chat_id and msg_id and pub_timestamp):
        logger.debug("Skipping result with missing required fields: %s", result)
        return None
    return {
        "type": sighting_type(result),
        "source": f"Telegram/{encrypt_source_fragment(aesgcm, chat_id, msg_id)}",
        "vulnerability": vuln_id,
        "creation_timestamp": pub_timestamp,
    }


def push_sighting(
    client: PyVulnerabilityLookup, sighting: dict[str, Any]
) -> bool:
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
            "Start of the time window (epoch seconds or ISO 8601). "
            "Defaults to 24 hours before --until."
        ),
    )
    parser.add_argument(
        "--until",
        help="End of the time window (epoch seconds or ISO 8601). Defaults to now.",
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
        else int((datetime.fromtimestamp(until, tz=timezone.utc) - DEFAULT_WINDOW).timestamp())
    )
    if since >= until:
        logger.error("--since (%d) must be earlier than --until (%d)", since, until)
        return 2

    aesgcm = load_aesgcm(getattr(config, "source_encryption_key", None))
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
    ):
        seen += 1
        sighting = build_sighting(aesgcm, result)
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
        verb, pushed, seen, since, until,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
