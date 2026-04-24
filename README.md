# TeleGramSight

A client that retrieves vulnerability observations from Telegram and pushes them to a
[Vulnerability-Lookup](https://github.com/vulnerability-lookup/vulnerability-lookup) instance.


## Installation


[pipx](https://github.com/pypa/pipx) is an easy way to install and run Python applications in isolated environments.
It's easy to [install](https://github.com/pypa/pipx?tab=readme-ov-file#on-linux).


```bash
$ pipx install TeleGramSight
$ export TeleGramSight_CONFIG=~/conf.py
```

The configuration should be defined in a Python file (e.g., ``~/.TeleGramSight/conf.py``).
You must then set an environment variable (``TeleGramSight_CONFIG``) with the full path to this file.


## Usage

Once installed and configured, invoke the CLI:

```bash
$ telegramsight --since 2026-04-23T00:00:00 --until 2026-04-24T00:00:00
```

Arguments:

- `--since` / `--until` — time window bounds. Accept epoch seconds or ISO 8601 timestamps.
  Defaults to the last 24 hours when omitted, which is the expected cron invocation.
- `--page-size` — results per API call (default 100).
- `--no-push` — dry run: fetch and build sightings and log them, but don't send anything to Vulnerability-Lookup.

Cron example (every hour):

```cron
0 * * * * TeleGramSight_CONFIG=/etc/telegramsight/conf.py /usr/local/bin/telegramsight
```

## Security

Sighting sources are encrypted with AES-256-GCM using the `source_encryption_key`
set in your configuration file. AES-256 retains an estimated ~128-bit security
margin against known quantum attacks (Grover's algorithm), but the tool itself
has not been independently audited or certified.

## License

[TeleGramSight](https://github.com/vulnerability-lookup/TeleGramSight) is licensed under
[GNU General Public License version 3](https://www.gnu.org/licenses/gpl-3.0.html)

~~~
Copyright (c) 2026 Computer Incident Response Center Luxembourg (CIRCL)
Copyright (C) 2026 Cédric Bonhomme - https://github.com/cedricbonhomme
~~~
