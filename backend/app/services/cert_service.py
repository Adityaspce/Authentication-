# backend/app/routes/cert_route.py
from fastapi import APIRouter, File, Form, UploadFile
from io import BytesIO
import hashlib
import base64
import json
import PyPDF2

from app.services.crypto_service import CryptoService
from app.services.ipfs_service import upload_file_to_ipfs
from app.services.cert_service import extract_metadata

router = APIRouter()
cs = CryptoService()


@router.post("/process")
async def process_certificate(
    file: UploadFile = File(...),
    recipient_pub: str = Form(...)
):
    """
    Process a certificate PDF:
      1. Read file
      2. Compute SHA256 hash
      3. Extract metadata
      4. Generate core hash (metadata + file hash)
      5. Encrypt PDF with AES-GCM
      6. Wrap AES key with recipient Ed25519 pubkey
      7. Upload encrypted PDF to IPFS
      8. Return JSON with hashes, wrapped key, and IPFS CID
    """
    # 1️⃣ Read file bytes
    file_bytes = await file.read()

    # 2️⃣ SHA256 file hash
    file_hash = hashlib.sha256(file_bytes).hexdigest()

    # 3️⃣ Extract metadata
    reader = PyPDF2.PdfReader(BytesIO(file_bytes))
    text_content = "".join([page.extract_text() or "" for page in reader.pages])
    metadata = extract_metadata(file_bytes)

    # 4️⃣ Core hash = SHA256(metadata_json + file_hash)
    core_string = json.dumps(metadata, sort_keys=True) + file_hash
    core_hash = hashlib.sha256(core_string.encode()).hexdigest()

    # 5️⃣ AES-GCM encryption
    aes_key = cs.generate_aes_key()
    enc = cs.aes_encrypt(file_bytes, aes_key)
    ciphertext, nonce, tag = enc["ciphertext"], enc["nonce"], enc["tag"]

    # 6️⃣ Wrap AES key with recipient Ed25519 public key
    wrapped_key = cs.wrap_key_to_ed25519_pub(recipient_pub, aes_key)

    # 7️⃣ Upload ciphertext to IPFS
    ipfs_cid = upload_file_to_ipfs(ciphertext)

    # 8️⃣ Return JSON
    return {
        "metadata": metadata,
        "file_hash": file_hash,
        "core_hash": core_hash,
        "ipfs_cid": ipfs_cid,
        "wrapped_key": base64.b64encode(wrapped_key).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "tag": base64.b64encode(tag).decode()
    }


@router.post("/cert/anchor")
async def anchor_certificate(core_hash: str = Form(...)):
    """
    Anchor core_hash to Solana blockchain.
    (Currently stub for Anchor integration)
    """
    try:
        # TODO: connect to Anchor smart contract
        return {"status": "success", "core_hash": core_hash, "tx": "mock_tx_id"}
    except Exception as e:
        return {"status": "error", "details": str(e)}


@router.post("/cert/verify")
async def verify_certificate(file: UploadFile = File(...)):
    """
    Verify uploaded certificate against blockchain.
    (Currently stub for Anchor integration)
    """
    file_bytes = await file.read()
    reader = PyPDF2.PdfReader(BytesIO(file_bytes))
    text_content = "".join([page.extract_text() or "" for page in reader.pages])
    # Verification logic: core hash
    core_hash = hashlib.sha256(text_content.encode()).hexdigest()

    return {"core_hash": core_hash, "verification": "NOT IMPLEMENTED FULLY"}
