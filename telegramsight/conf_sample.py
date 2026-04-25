# Telegram sightings source.
# Do NOT commit the real URL or api_key — keep them in your non-versioned
# conf.py (pointed at by the TeleGramSight_CONFIG environment variable).
api_url = ""
api_key = ""

# Whether to ask the upstream API to include the message text (`msg=true`)
# in each result. Set to False to fetch metadata only.
include_msg = True

vulnerability_lookup_base_url = "https://vulnerability.circl.lu/"
vulnerability_auth_token = ""

# AES-SIV key used to deterministically encrypt the chat_id/msg_id fragment
# of the sighting source. urlsafe-base64 of 32, 48, or 64 raw bytes
# (AES-128-SIV, AES-192-SIV, AES-256-SIV respectively). Generate a 64-byte
# (AES-256-SIV) key with:
#   python -c "import base64, os; print(base64.urlsafe_b64encode(os.urandom(64)).decode().rstrip('='))"
source_encryption_key = ""

# Heartbeat mechanism
heartbeat_enabled = True
valkey_host = "127.0.0.1"
valkey_port = 10002
expiration_period = 18000
