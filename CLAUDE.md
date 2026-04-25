# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Purpose

Cron-invoked CLI that pulls vulnerability sightings collected by a third-party Telegram scraper and pushes them to a [Vulnerability-Lookup](https://github.com/vulnerability-lookup/vulnerability-lookup) instance via `pyvulnerabilitylookup`. Sibling project to MISPSight — same config-file pattern.

## Tooling and commands

- Build/packaging: Poetry (`poetry-core >=2.0.0,<3.0.0`), Python `>=3.10,<4.0`.
- Install for development: `poetry install` (pulls the `dev` dependency group).
- Install as a user tool: `pipx install TeleGramSight` (exposes the `telegramsight` entry point defined in `[project.scripts]`).
- Runtime deps: `requests`, `pyvulnerabilitylookup`, `cryptography` (AES-SIV), `dateparser` (natural-language `--since`/`--until`).
- Type-check: `poetry run mypy .` — this is the **only** quality gate that CI enforces. `.github/workflows/mypy.yml` runs it on Python 3.11, 3.12, and 3.13 on every push/PR to `main`. The `[tool.mypy]` block in `pyproject.toml` is strict (`strict_optional`, `no_implicit_optional`, `warn_unreachable`, etc.); fix issues at the source rather than adding blanket `# type: ignore`.
- No test suite is checked in.

## Architecture

Single-file flow in `telegramsight/main.py`:

1. `load_config()` reads the Python file pointed at by `TeleGramSight_CONFIG` — the env var name is mixed-case and matches the one in the README; don't normalise it.
2. `iter_results()` POSTs to `{api_url}/api/get_cve_objs` with `tag_llm=True`, paginating via `page`/`page_size` until `page * page_size >= total`.
3. `sighting_type()` maps Telegram tags to a Vulnerability-Lookup sighting type:
   - `tag_wildusage` → `exploited`
   - `tag_poc` → `published-proof-of-concept`
   - otherwise → `seen`
   (`tag_wildusage` wins when both are set — checked first.)
4. `build_sighting()` assembles `{type, source=Telegram/{enc}, vulnerability, creation_timestamp}` and `push_sighting()` calls `PyVulnerabilityLookup.create_sighting`.
   - `{enc}` is AES-SIV(`"{chat_id}/{msg_id}"`) under `source_encryption_key` with no nonce and no associated data, serialized as urlsafe-base64 of `SIV (16B) || ciphertext` (padding stripped). This is *deterministic on purpose*: the same Telegram message always produces the same source string, so Vulnerability-Lookup can dedupe on the ciphertext without decrypting. Key may be 32/48/64 raw bytes (AES-128/192/256-SIV). If you ever need to change the key, all previously-pushed sightings become undiscoverable under the new key.
   - `creation_timestamp` must be a timezone-aware `datetime` (not the raw ISO string from the upstream API) — `create_sighting` inspects `.tzinfo`. Naive timestamps are coerced to UTC.

## Config split — do not break this

The Telegram endpoint URL is deliberately kept out of source control:

- `telegramsight/conf_sample.py` — **versioned template**. `api_url` / `api_key` / `source_encryption_key` must stay blank here; no real URL or key in comments either.
- `telegramsight/conf.py` — **gitignored** (see `.gitignore`). This is where the real `api_url` and `source_encryption_key` live. Deployments point `TeleGramSight_CONFIG` at a copy of this file outside the repo.

When adding new config keys, add them to `conf_sample.py` with empty/default values, and to `conf.py` if local dev needs them. Never paste secrets or private endpoints into `conf_sample.py`.

## CLI contract

`telegramsight [--since <t>] [--until <t>] [--page-size N] [--no-push]`

- `--since` / `--until` accept unix-epoch seconds, ISO 8601 timestamps, or natural-language expressions (`2 days ago`, `yesterday`, `today`). With no args the tool runs over the last 24 hours — that is the intended cron shape, so don't change the default window without updating the README's cron example.
- `--no-push` is a dry run: build and log each sighting but don't instantiate `PyVulnerabilityLookup` or call out to the instance.

## Release process

1. Land all changes on `main` and get `mypy` green (CI will block otherwise).
2. Bump `version` in `pyproject.toml`.
3. Add a dated section to `CHANGELOG.md` following Keep-a-Changelog (`Added` / `Changed` / `Fixed` / …) and append the link reference at the bottom.
4. Commit as `chg: [release] Prepare <version>.`.
5. Create an **annotated** tag `v<version>` whose message mirrors the CHANGELOG entry (`git tag -a v<version> -m "…"`). Tags are PGP-signed by the maintainer's git config — don't override that.
6. Push commits and tag (`git push --follow-tags`).
7. Publish a GitHub Release from the tag — `.github/workflows/release.yml` picks that up and trust-publishes the wheel to PyPI (the tag push alone does not trigger publishing).

Commit-message convention in the log: `chg: [area] …` for non-bug changes, `fix: [area] …` for bug fixes.

## License

GPL-3.0-or-later. New files should be compatible with that license.
