# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] - 2026-04-30

### Added

- `telegramsight-decrypt <fragment>` CLI helper, registered as a second
  entry point in `[project.scripts]`. Lets an operator holding the
  `source_encryption_key` recover the original `{chat_id}/{msg_id}`
  behind an opaque `Telegram/<ct>` sighting source for investigation.
  Accepts either the raw urlsafe-base64 ciphertext or the full
  `Telegram/<ct>` string copied from a sighting. Reads the same
  `TeleGramSight_CONFIG` file as the main CLI and runs entirely
  locally — no network calls — so the privacy guarantee around
  private-channel chat ids is preserved: only key-holders can resolve
  them.

## [0.5.2] - 2026-04-29

### Fixed

- Transient failures talking to the Telegram collector (e.g.
  `ConnectionResetError(104, 'Connection reset by peer')`, refused
  connections, timeouts, 5xx responses) now retry automatically up to
  three times with exponential backoff before any exception bubbles up.
  If all retries fail (or the upstream returns a non-retryable error
  like 4xx), the run logs a single `ERROR` line and exits with status
  3 instead of dumping a traceback — cron-friendly behaviour.

## [0.5.1] - 2026-04-29

### Fixed

- **Privacy:** message text could be attached to a sighting whose
  `source` had fallen back to the encrypted `Telegram/<aes-siv>` form.
  This happened when the channel URL passed the public-username regex
  but the `username` field returned by the upstream collector was
  missing, empty, `None`, or otherwise didn't validate. The source
  correctly became opaque, but the `content` gate was looser than the
  source gate, so message text from such channels was being pushed to
  Vulnerability-Lookup. The two gates are now structural rather than
  conditional: the line that attaches `content` lives inside the same
  branch that builds the public `https://t.me/<username>/<msg_id>`
  source, so a hidden source can never carry text. Operators running
  0.5.0 with `include_text = True` should audit their
  Vulnerability-Lookup instance for sightings whose `source` matches
  `Telegram/%` and whose `content` field is set, and remove them.

## [0.5.0] - 2026-04-25

### Changed

- Sighting `source` for **public** channels is now the canonical
  `https://t.me/<username>/<msg_id>` link — clickable from
  Vulnerability-Lookup straight to the originating Telegram message.
  Private channels (and any case where the channel URL says "public"
  but the `username` field is missing or doesn't match the Telegram
  username rule) still get the deterministic `Telegram/<aes-siv>`
  identifier so chat ids and message ids are never exposed in the
  clear. The asymmetry is intentional: public sources double as a
  human-followable link, private sources stay opaque.

  **Migration note:** sources for public-channel sightings produced by
  0.4.x were AES-SIV ciphertexts; from 0.5.0 they're plaintext URLs.
  Previously-pushed sightings will not dedupe against new ones for the
  same public message.

## [0.4.0] - 2026-04-25

### Added

- `include_msg` config option (default `True`) — controls whether the
  upstream Telegram collector is asked to include message text in each
  result (`msg=true` payload field). Set to `False` for metadata-only
  responses.
- `include_text` config option (default `False`) — when `True`, attaches
  the message text to each sighting pushed to Vulnerability-Lookup as
  the `content` field. **Privacy guarantee:** text is *only* attached
  for public channels (those whose `t.me` URL points at a Telegram
  username matching `^[A-Za-z][A-Za-z0-9_]{4,31}$`). Messages from
  private channels — identified by a numeric chat_id in the URL,
  `/c/<id>/...` permalinks, `+invite_hash` invite links, or a missing
  channel field — are never sent regardless of the flag.

### Changed

- Widened the `pyvulnerabilitylookup` dependency constraint from
  `>=2.0.0,<3.0.0` to `>=2.0.0,<5.0.0`.

### Fixed

- Python classifier list in `pyproject.toml` was duplicating
  `Programming Language :: Python :: 3.12` three times; now correctly
  lists 3.10 through 3.14.

## [0.3.0] - 2026-04-25

### Fixed

- `tag_poc` Telegram tag now maps to the sighting type
  `published-proof-of-concept` instead of `proof_of_concept`, to match
  the vocabulary expected by Vulnerability-Lookup. Sightings pushed by
  earlier 0.x versions therefore carry the wrong sighting type.

## [0.2.0] - 2026-04-24

### Changed

- Source-fragment encryption switched from AES-256-GCM to **AES-SIV**
  (RFC 5297), invoked deterministically with no nonce and no associated
  data. The same Telegram message now always produces the same
  `Telegram/<ciphertext>` source string, so Vulnerability-Lookup can
  deduplicate on the ciphertext without having to decrypt it. Plaintext
  is still recoverable with the key. `source_encryption_key` accepts
  32-, 48-, or 64-byte keys (AES-128/192/256-SIV); 64 bytes is
  recommended for new deployments. **Migration note:** source strings
  pushed by 0.1.x (AES-GCM with a per-record random nonce) will not
  dedupe against strings produced by 0.2.0 for the same underlying
  message.
- Telegram-tag precedence inverted: `tag_wildusage` (→ `exploited`) now
  wins over `tag_poc` (→ `proof_of_concept`) when both are set.

### Dependencies

- Bumped `cryptography` from 45.0.7 to 46.0.7.

## [0.1.1] - 2026-04-24

### Fixed

- `creation_timestamp` is now passed to `PyVulnerabilityLookup.create_sighting`
  as a timezone-aware `datetime` instead of the raw ISO 8601 string returned
  by the upstream API, avoiding a `'str' object has no attribute 'tzinfo'`
  error that caused every sighting push to fail.

## [0.1.0] - 2026-04-24

Initial release.

### Added

- `telegramsight` CLI that pulls vulnerability sightings from a Telegram
  collector API (`POST /api/get_cve_objs`) and pushes them to a
  Vulnerability-Lookup instance via `pyvulnerabilitylookup`.
- `--since` / `--until` time-window flags accepting unix-epoch seconds,
  ISO 8601 timestamps, or natural-language expressions (e.g. `2 days ago`,
  `yesterday`, `today`); default window is the last 24 hours so the tool
  is cron-friendly with no arguments.
- `--page-size` flag to tune pagination (default 100).
- `--no-push` dry-run flag that builds and logs each sighting without
  contacting the Vulnerability-Lookup instance.
- Telegram-tag → Vulnerability-Lookup sighting-type mapping: `tag_poc` →
  `proof_of_concept`, `tag_wildusage` → `exploited`, otherwise `seen`.
- AES-256-GCM encryption of the `chat_id/msg_id` fragment of each sighting
  `source`, using a `source_encryption_key` supplied in the runtime config
  (a fresh 12-byte nonce is generated per sighting).
- Config split between `telegramsight/conf_sample.py` (versioned template)
  and a gitignored `telegramsight/conf.py`; the runtime config path is
  resolved from the `TeleGramSight_CONFIG` environment variable.

[0.6.0]: https://github.com/vulnerability-lookup/TeleGramSight/releases/tag/v0.6.0
[0.5.2]: https://github.com/vulnerability-lookup/TeleGramSight/releases/tag/v0.5.2
[0.5.1]: https://github.com/vulnerability-lookup/TeleGramSight/releases/tag/v0.5.1
[0.5.0]: https://github.com/vulnerability-lookup/TeleGramSight/releases/tag/v0.5.0
[0.4.0]: https://github.com/vulnerability-lookup/TeleGramSight/releases/tag/v0.4.0
[0.3.0]: https://github.com/vulnerability-lookup/TeleGramSight/releases/tag/v0.3.0
[0.2.0]: https://github.com/cedricbonhomme/TeleGramSight/releases/tag/v0.2.0
[0.1.1]: https://github.com/cedricbonhomme/TeleGramSight/releases/tag/v0.1.1
[0.1.0]: https://github.com/cedricbonhomme/TeleGramSight/releases/tag/v0.1.0
