import json, base64, requests, os
from app.services.crypto_service import CryptoService

cs = CryptoService()

# Load response from backend
r = json.load(open("response.json"))
cid = r["ipfs_cid"]
wrapped = base64.b64decode(r["wrapped_key"])
nonce = base64.b64decode(r["nonce"])
tag = base64.b64decode(r["tag"])

# Fetch ciphertext from local IPFS
ciphertext = requests.get(f"http://127.0.0.1:8080/ipfs/{cid}").content

# Load your Solana private key bytes (default id.json)
priv_path = os.path.expanduser("~/.config/solana/id.json")
priv_bytes = bytes(json.load(open(priv_path)))

# Unwrap AES key
aes_key = cs.unwrap_key_with_ed25519_priv(priv_bytes, wrapped)

# Decrypt the file
plaintext = cs.aes_decrypt(ciphertext, nonce, tag, aes_key)

# Save decrypted file
with open("decrypted_certificate.pdf", "wb") as f:
    f.write(plaintext)

print("Decrypted file created: decrypted_certificate.pdf")

