# backend/app/services/crypto_service.py
import os
from typing import Dict, Union

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

import nacl.public
import nacl.signing
import nacl.bindings
import nacl.exceptions
import base58


class CryptoError(Exception):
    pass


class CryptoService:
    """
    Hybrid ECC (Ed25519/X25519 SealedBox) + AES-GCM service.

    Main functions:
      - generate_aes_key(length=32) -> bytes
      - aes_encrypt(plaintext, key) -> {"ciphertext": bytes, "nonce": bytes, "tag": bytes}
      - aes_decrypt(ciphertext, nonce, tag, key) -> bytes
      - wrap_key_to_ed25519_pub(pubkey, aes_key) -> bytes (sealed)
      - unwrap_key_with_ed25519_priv(privkey, sealed_key) -> bytes
      - verify_ed25519_signature(pubkey, message, signature) -> bool
    """

    def __init__(self):
        self.backend = default_backend()

    # ---------- Symmetric AES-GCM ----------
    @staticmethod
    def generate_aes_key(length: int = 32) -> bytes:
        if length not in (16, 24, 32):
            raise CryptoError("AES key length must be 16, 24, or 32 bytes")
        return os.urandom(length)

    def aes_encrypt(self, plaintext: bytes, key: bytes) -> Dict[str, bytes]:
        if not isinstance(plaintext, (bytes, bytearray)):
            raise CryptoError("Plaintext must be bytes")
        if len(key) not in (16, 24, 32):
            raise CryptoError("AES key length invalid")

        nonce = os.urandom(12)
        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
            backend=self.backend
        ).encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return {"ciphertext": ciphertext, "nonce": nonce, "tag": encryptor.tag}

    def aes_decrypt(self, ciphertext: bytes, nonce: bytes, tag: bytes, key: bytes) -> bytes:
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce, tag),
            backend=self.backend
        ).decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    # ---------- Helpers: Solana Ed25519 ↔ X25519 ----------
    @staticmethod
    def _ensure_bytes(key_in: Union[str, bytes]) -> bytes:
        if isinstance(key_in, str):
            try:
                return base58.b58decode(key_in)
            except Exception:
                try:
                    return bytes.fromhex(key_in)
                except Exception:
                    raise CryptoError("Unsupported key string format")
        if isinstance(key_in, (bytes, bytearray)):
            return bytes(key_in)
        raise CryptoError("Unsupported key type")

    @staticmethod
    def ed25519_pub_to_x25519_pub(ed_pub: bytes) -> bytes:
        if len(ed_pub) != 32:
            raise CryptoError("Ed25519 public key must be 32 bytes")
        return nacl.bindings.crypto_sign_ed25519_pk_to_curve25519(ed_pub)

    @staticmethod
    def ed25519_priv_to_x25519_priv(ed_priv: bytes) -> bytes:
        if len(ed_priv) == 64:
            return nacl.bindings.crypto_sign_ed25519_sk_to_curve25519(ed_priv)
        if len(ed_priv) == 32:
            signing_key = nacl.signing.SigningKey(ed_priv)
            sk64 = signing_key._seed + signing_key.verify_key.encode()
            return nacl.bindings.crypto_sign_ed25519_sk_to_curve25519(sk64)
        raise CryptoError("Ed25519 private key must be 32 or 64 bytes")

    # ---------- Key wrapping ----------
    def wrap_key_to_ed25519_pub(self, ed_pub: Union[str, bytes], aes_key: bytes) -> bytes:
        ed_pub_bytes = self._ensure_bytes(ed_pub)
        x_pub = self.ed25519_pub_to_x25519_pub(ed_pub_bytes)
        recipient_pk = nacl.public.PublicKey(x_pub)
        return nacl.public.SealedBox(recipient_pk).encrypt(aes_key)

    def unwrap_key_with_ed25519_priv(self, ed_priv: Union[str, bytes], sealed_key: bytes) -> bytes:
        priv_bytes = self._ensure_bytes(ed_priv)
        x_priv = self.ed25519_priv_to_x25519_priv(priv_bytes)
        privkey_obj = nacl.public.PrivateKey(x_priv)
        try:
            return nacl.public.SealedBox(privkey_obj).decrypt(sealed_key)
        except nacl.exceptions.CryptoError as e:
            raise CryptoError("Failed to unwrap sealed AES key") from e

    # ---------- Ed25519 signature verification ----------
    @staticmethod
    def verify_ed25519_signature(ed_pub: Union[str, bytes], message: bytes, signature: bytes) -> bool:
        pub_bytes = CryptoService._ensure_bytes(ed_pub)
        if len(pub_bytes) != 32:
            raise CryptoError("Ed25519 public key must be 32 bytes")
        try:
            verify_key = nacl.signing.VerifyKey(pub_bytes)
            verify_key.verify(message, signature)
            return True
        except Exception:
            raise CryptoError("Signature verification failed")
