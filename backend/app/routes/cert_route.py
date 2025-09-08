# backend/app/routes/cert_route.py
from fastapi import APIRouter, File, Form, UploadFile
import hashlib, base64, json
from io import BytesIO
from PyPDF2 import PdfReader
from app.services.crypto_service import CryptoService
from app.services.ipfs_service import upload_file_to_ipfs
from app.utils.pdf_utils import extract_metadata
from app.services.cert_store import save_certificate, get_certificate

router = APIRouter()
cs = CryptoService()

# ---------------- /process ----------------
@router.post("/process")
async def process_certificate(
    file: UploadFile = File(...),
    recipient_pub: str = Form(...)
):
    """
    Process a certificate PDF:
    1. Hash the file
    2. Extract metadata
    3. Generate core_hash
    4. Encrypt PDF with AES-GCM
    5. Wrap AES key with recipient Ed25519 pubkey
    6. Upload encrypted PDF to IPFS
    7. Return JSON with all necessary info
    """
    # 1️⃣ Read file bytes
    file_bytes = await file.read()

    # 2️⃣ Compute SHA256 file hash
    file_hash = hashlib.sha256(file_bytes).hexdigest()

    # 3️⃣ Extract metadata from PDF
    metadata = extract_metadata(file_bytes)  # must accept bytes

    # 4️⃣ Generate core hash (metadata JSON + file hash)
    core_string = json.dumps(metadata, sort_keys=True) + file_hash
    core_hash = hashlib.sha256(core_string.encode()).hexdigest()

    # 5️⃣ AES-GCM encryption
    aes_key = cs.generate_aes_key()
    enc = cs.aes_encrypt(file_bytes, aes_key)
    ciphertext, nonce, tag = enc["ciphertext"], enc["nonce"], enc["tag"]

    # 6️⃣ Wrap AES key with recipient Ed25519 public key
    wrapped_key = cs.wrap_key_to_ed25519_pub(recipient_pub, aes_key)

    # 7️⃣ Upload encrypted PDF to IPFS
    ipfs_cid = upload_file_to_ipfs(ciphertext)

    # 8️⃣ Return JSON with base64 encoded bytes
    return {
        "metadata": metadata,
        "file_hash": file_hash,
        "core_hash": core_hash,
        "ipfs_cid": ipfs_cid,
        "wrapped_key": base64.b64encode(wrapped_key).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "tag": base64.b64encode(tag).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }

# ---------------- /anchor ----------------
@router.post("/cert/anchor")
async def anchor_certificate(
    core_hash: str = Form(...),
    ipfs_cid: str = Form(...),
    metadata: str = Form(...),
    recipient_pub: str = Form(...)
):
    """
    Anchor a certificate core_hash to blockchain (mocked here).
    Saves certificate info in-memory for verification.
    """
    # Mock blockchain transaction ID
    tx_id = f"mock_tx_{core_hash[:8]}"

    # Save record in memory
    save_certificate(core_hash, ipfs_cid, json.loads(metadata), recipient_pub, tx_id)

    return {"status": "success", "core_hash": core_hash, "tx_id": tx_id}

# ---------------- /verify ----------------
@router.post("/cert/verify")
async def verify_certificate(file: UploadFile = File(...)):
    """
    Verify uploaded certificate PDF against anchored records (mock verification).
    """
    file_bytes = await file.read()
    metadata = extract_metadata(file_bytes)
    file_hash = hashlib.sha256(file_bytes).hexdigest()
    core_string = json.dumps(metadata, sort_keys=True) + file_hash
    core_hash = hashlib.sha256(core_string.encode()).hexdigest()

    record = get_certificate(core_hash)
    verification_status = "VERIFIED" if record else "NOT VERIFIED"

    return {
        "core_hash": core_hash,
        "verification": verification_status,
        "record": record
    }
