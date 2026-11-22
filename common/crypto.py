
import os
import hmac
import hashlib
import secrets
from typing import Tuple

# Cryptography library — stdlib in Python 3.10+
# (cryptography package is the de-facto standard; fallback: pycryptodome)
try:
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.padding import PKCS7
    from cryptography.hazmat.backends import default_backend
    _BACKEND = "cryptography"
except ImportError:  # pragma: no cover — documented fallback
    _BACKEND = None


# ── Constants ────────────────────────────────────────────────────────────────
RSA_KEY_BITS = 2048
AES_KEY_BYTES = 32                 # AES-256
HMAC_KEY_BYTES = 32                # HMAC-SHA256
IV_BYTES = 16                      # AES block size = 128 bit
HMAC_TAG_BYTES = 32                # SHA-256 digest

# RSA OAEP padding for session-key transport
_RSA_PADDING = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


# ── RSA keypair generation ───────────────────────────────────────────────────

def generate_rsa_keypair():
    """Generate an RSA-2048 keypair.

    Returns (private_key, public_key) from `cryptography`.
    Used by both client (for AUTH) and server (for AUTH_ACK signing).
    """
    if _BACKEND is None:
        raise RuntimeError("'cryptography' package not installed: pip install cryptography")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_BITS,
        backend=default_backend(),
    )
    return private_key, private_key.public_key()


def serialize_public_key(public_key) -> bytes:
    """PEM-encode a public key for transmission in AUTH/AUTH_ACK."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_public_key(pem_bytes: bytes):
    """Deserialize a PEM-encoded public key."""
    return serialization.load_pem_public_key(pem_bytes, backend=default_backend())


def load_private_key(pem_bytes: bytes, password: bytes = None):
    """Deserialize a PEM-encoded private key (PKCS#8)."""
    return serialization.load_pem_private_key(
        pem_bytes, password=password, backend=default_backend()
    )


# ── Session key generation & transport ──────────────────────────────────────

def generate_session_keys() -> Tuple[bytes, bytes]:
    """Generate a fresh (AES-256 key, HMAC-SHA256 key) pair.

    Both keys are 32 bytes drawn from a CSPRNG (secrets.token_bytes).
    The server generates these once per client login (Báo cáo §8.1).
    """
    return secrets.token_bytes(AES_KEY_BYTES), secrets.token_bytes(HMAC_KEY_BYTES)


def encrypt_session_keys_for_client(aes_key: bytes, hmac_key: bytes,
                                    client_public_key) -> bytes:
    """Wrap (aes_key || hmac_key) under the client's RSA public key.

    The server calls this when building AUTH_ACK. Total payload = 64 bytes,
    well under the RSA-2048 OAEP maximum (~190 bytes with SHA-256).
    """
    blob = aes_key + hmac_key
    return client_public_key.encrypt(blob, _RSA_PADDING)


def decrypt_session_keys(ciphertext: bytes, client_private_key) -> Tuple[bytes, bytes]:
    """Unwrap (aes_key, hmac_key) on the client side."""
    blob = client_private_key.decrypt(ciphertext, _RSA_PADDING)
    if len(blob) != AES_KEY_BYTES + HMAC_KEY_BYTES:
        raise ValueError("decrypted session-key blob has wrong length")
    return blob[:AES_KEY_BYTES], blob[AES_KEY_BYTES:]


# ── AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC) ───────────────────────────

def encrypt_payload(plaintext: bytes, aes_key: bytes, hmac_key: bytes) -> bytes:
    """Encrypt-then-MAC a payload.

    Output layout: [IV (16)] [ciphertext (len(plaintext) + padding)]
                   [HMAC-SHA256 tag (32)]

    HMAC is computed over (IV || ciphertext), per Encrypt-then-MAC.
    This is the safest ordering against padding-oracle attacks.
    """
    # 1. Generate a fresh random IV for each payload.
    iv = secrets.token_bytes(IV_BYTES)

    # 2. PKCS#7-pad plaintext to AES block size (128-bit), then encrypt.
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    # 3. HMAC over (IV || ciphertext) — Encrypt-then-MAC.
    tag = hmac.new(hmac_key, iv + ciphertext, hashlib.sha256).digest()

    return iv + ciphertext + tag


def decrypt_payload(blob: bytes, aes_key: bytes, hmac_key: bytes) -> bytes:
    """Verify HMAC then decrypt. Raises ValueError on tamper."""
    if len(blob) < IV_BYTES + HMAC_TAG_BYTES:
        raise ValueError("ciphertext blob too short")
    iv = blob[:IV_BYTES]
    tag = blob[-HMAC_TAG_BYTES:]
    ciphertext = blob[IV_BYTES:-HMAC_TAG_BYTES]

    # 1. Constant-time HMAC verification (defense against timing attacks).
    expected = hmac.new(hmac_key, iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise ValueError("HMAC verification failed — payload tampered or wrong key")

    # 2. Decrypt and unpad.
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


# ── File integrity (SHA-256 of whole file) ────────────────────────────────

def sha256_file(path: str, chunk: int = 65536) -> str:
    """Compute the SHA-256 hex digest of a file.

    Used in FILE_INIT to let the receiver verify end-to-end integrity
    after reassembly (Báo cáo §8.3). MD5 is rejected (Ch.8 slide 48 —
    MD5 collisions are practical); SHA-256 has no practical collision.
    """
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    """SHA-256 hex digest of an in-memory byte string."""
    return hashlib.sha256(data).hexdigest()
