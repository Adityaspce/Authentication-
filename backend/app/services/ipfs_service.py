import requests

IPFS_API = "http://127.0.0.1:5001/api/v0/add"

def ipfs_client_upload_bytes(data: bytes) -> str:
    files = {"file": ("file.bin", data)}
    resp = requests.post(IPFS_API, files=files)
    resp.raise_for_status()
    return resp.json()["Hash"]

def upload_file_to_ipfs(file_bytes):
    """
    Uploads file bytes to IPFS (local daemon).
    Returns the CID.
    """
    import requests

    # Assuming local IPFS daemon API
    response = requests.post(
        "http://127.0.0.1:5001/api/v0/add",
        files={"file": file_bytes}
    )
    cid = response.json()["Hash"]
    return cid
