import os
from dotenv import load_dotenv
load_dotenv()

env_vault_token = os.getenv("PANGEA_VAULT_TOKEN")
pangea_vault_audit_id=os.getenv("PANGEA_VAULT_AUDIT_ID")  # vault id for an audit login token
pangea_vault_ipintel_id=os.getenv("PANGEA_VAULT_IPINTEL_ID") # vault id for an ip intel token
pangea_vault_userintel_id=os.getenv("PANGEA_VAULT_USERINTEL_ID") # vault id for a user intel token

