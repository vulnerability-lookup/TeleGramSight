# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.1.1]: https://github.com/cedricbonhomme/TeleGramSight/releases/tag/v0.1.1
[0.1.0]: https://github.com/cedricbonhomme/TeleGramSight/releases/tag/v0.1.0
