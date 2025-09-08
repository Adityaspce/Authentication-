try:
    # Old solana-py (<=0.25)
    from solana.transaction import Transaction
    from solana.rpc.api import Client
    from solana.keypair import Keypair
    from solana.system_program import TransferParams, transfer
except ImportError:
    # Newer solders-based SDK
    from solders.transaction import Transaction
    from solana.rpc.api import Client
    from solders.keypair import Keypair
    from solana.system_program import TransferParams, transfer

import json
from pathlib import Path

# Connect to devnet
client = Client("https://api.devnet.solana.com")

KEYPAIR_PATH = Path("backend/id.json")


def load_keypair() -> Keypair:
    """Load local Solana keypair from id.json."""
    if not KEYPAIR_PATH.exists():
        raise FileNotFoundError("Keypair file not found at backend/id.json")
    secret = json.load(open(KEYPAIR_PATH))
    return Keypair.from_secret_key(bytes(secret))


def anchor_hash_on_chain(core_hash: str, recipient_pub: str) -> str:
    """Send a minimal transaction embedding the certificate hash."""
    sender = load_keypair()
    recipient = recipient_pub

    # Very small transfer to create a tx (attach hash in memo later if needed)
    txn = Transaction().add(
        transfer(
            TransferParams(
                from_pubkey=sender.public_key,
                to_pubkey=recipient,
                lamports=1  # tiny transfer
            )
        )
    )

    resp = client.send_transaction(txn, sender)
    return resp["result"]
