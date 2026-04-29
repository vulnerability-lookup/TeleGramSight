# TeleGramSight

A client that retrieves vulnerability observations from a Telegram collector and pushes them to a
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
$ telegramsight --since 'yesterday' --until 'today' --no-push
$ telegramsight --since '2 days ago' --until 'today'
$ telegramsight --since 1775001600 --until 1776902399
```

Arguments:

- `--since` / `--until` — time window bounds. Accept unix-epoch seconds,
  ISO 8601 timestamps, or natural-language expressions (e.g. `2 days ago`,
  `yesterday`, `today`, `1 week ago`). Defaults to the last 24 hours when
  omitted, which is the expected cron invocation.
- `--page-size` — results per API call (default 100).
- `--no-push` — dry run: fetch and build sightings and log them, but don't send anything to Vulnerability-Lookup.

Cron example (every hour):

```cron
0 * * * * TeleGramSight_CONFIG=/etc/telegramsight/conf.py /usr/local/bin/telegramsight
```

### Decrypting a source fragment

Sightings coming from private channels carry an opaque `Telegram/<ct>` source
instead of a public `t.me/<user>/<id>` link, and never include the message
text (see [Security](#security)). When investigating such a sighting, an
operator who holds the `source_encryption_key` can recover
the underlying `<chat_id>/<msg_id>` locally with the `telegramsight-decrypt`
helper:

```bash
$ telegramsight-decrypt c3vSlSPcOR_UbD4dIs0S5bT1NWHke0QXkPNkd5-4SeE9
-1001234567890/42

$ telegramsight-decrypt 'Telegram/c3vSlSPcOR_UbD4dIs0S5bT1NWHke0QXkPNkd5-4SeE9'
-1001234567890/42
```

The command reads the same config file as `telegramsight` (via
`TeleGramSight_CONFIG`) and uses the same `source_encryption_key`. Decryption
happens entirely on the operator's machine — nothing is sent over the network
— so the privacy guarantee around private channels is preserved: the original
`chat_id` is only ever revealed to someone who already has the key.

## Security

Sighting sources are encrypted with AES-SIV (RFC 5297) using the
`source_encryption_key` set in your configuration file. AES-SIV is used
deterministically (no nonce, no associated data) so that the same Telegram
message always produces the same source string, which lets Vulnerability-Lookup
deduplicate on the ciphertext without decrypting it. The key may be 32, 48, or
64 bytes (AES-128/192/256-SIV); 64 bytes is recommended for new deployments.
AES-256 retains an estimated ~128-bit security margin against known quantum
attacks (Grover's algorithm), but the tool itself has not been independently
audited or certified.

## License

[TeleGramSight](https://github.com/vulnerability-lookup/TeleGramSight) is licensed under
[GNU General Public License version 3](https://www.gnu.org/licenses/gpl-3.0.html)

~~~
Copyright (c) 2026 Computer Incident Response Center Luxembourg (CIRCL)
Copyright (C) 2026 Cédric Bonhomme - https://github.com/cedricbonhomme
~~~
