# Telegram sightings source.
# Do NOT commit the real URL or api_key — keep them in your non-versioned
# conf.py (pointed at by the TeleGramSight_CONFIG environment variable).
api_url = ""
api_key = ""

vulnerability_lookup_base_url = "https://vulnerability.circl.lu/"
vulnerability_auth_token = ""

# AES-256-GCM key used to encrypt the chat_id/msg_id fragment of the sighting
# source. 32 raw bytes, urlsafe-base64 encoded. Generate with:
#   python -c "import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip('='))"
source_encryption_key = ""

# Heartbeat mechanism
heartbeat_enabled = True
valkey_host = "127.0.0.1"
valkey_port = 10002
expiration_period = 18000
