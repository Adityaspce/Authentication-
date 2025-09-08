# backend/app/services/cert_store.py
from typing import Dict

# Simple in-memory store: core_hash -> record
certificate_store: Dict[str, dict] = {}

def save_certificate(core_hash: str, ipfs_cid: str, metadata: dict, recipient_pub: str, tx_id: str):
    """
    Save a certificate record in memory.
    """
    certificate_store[core_hash] = {
        "ipfs_cid": ipfs_cid,
        "metadata": metadata,
        "recipient_pub": recipient_pub,
        "tx_id": tx_id
    }

def get_certificate(core_hash: str):
    """
    Retrieve a certificate record by core_hash.
    Returns None if not found.
    """
    return certificate_store.get(core_hash)
