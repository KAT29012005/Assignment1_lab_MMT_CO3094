

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.crypto import (
    generate_rsa_keypair, serialize_public_key, load_public_key,
    generate_session_keys,
    encrypt_session_keys_for_client, decrypt_session_keys,
    encrypt_payload, decrypt_payload,
    sha256_file, sha256_bytes,
)


class TestRSAKeyExchange(unittest.TestCase):
    """End-to-end RSA + session-key transport (Báo cáo §8.1)."""

    def test_keypair_generation(self):
        priv, pub = generate_rsa_keypair()
        # PEM must be ASCII and contain RSA PUBLIC KEY header
        pem = serialize_public_key(pub)
        self.assertIn(b"BEGIN PUBLIC KEY", pem)
        # Round-trip
        reloaded = load_public_key(pem)
        self.assertEqual(
            reloaded.public_numbers().n,
            pub.public_numbers().n,
        )

    def test_session_key_transport_round_trip(self):
        # Server side
        client_priv, client_pub = generate_rsa_keypair()
        aes_key, hmac_key = generate_session_keys()
        self.assertEqual(len(aes_key), 32)
        self.assertEqual(len(hmac_key), 32)
        ciphertext = encrypt_session_keys_for_client(aes_key, hmac_key, client_pub)

        # Client side
        got_aes, got_hmac = decrypt_session_keys(ciphertext, client_priv)
        self.assertEqual(got_aes, aes_key)
        self.assertEqual(got_hmac, hmac_key)


class TestAESEncryptThenMAC(unittest.TestCase):
    """Encrypt-then-MAC: decrypt(encrypt(x)) == x, and tamper fails."""

    def test_round_trip_small(self):
        aes, mac = generate_session_keys()
        plaintext = b"hello, secret world"
        blob = encrypt_payload(plaintext, aes, mac)
        self.assertEqual(decrypt_payload(blob, aes, mac), plaintext)

    def test_round_trip_large(self):
        aes, mac = generate_session_keys()
        plaintext = os.urandom(64 * 1024)        # 64 KB
        blob = encrypt_payload(plaintext, aes, mac)
        self.assertEqual(decrypt_payload(blob, aes, mac), plaintext)

    def test_round_trip_vietnamese(self):
        aes, mac = generate_session_keys()
        plaintext = "Chào bạn, đây là tin nhắn mật.".encode("utf-8")
        blob = encrypt_payload(plaintext, aes, mac)
        self.assertEqual(decrypt_payload(blob, aes, mac), plaintext)

    def test_iv_is_random_per_encryption(self):
        """Two encryptions of the same plaintext must produce different
        ciphertexts (random IV — Ch.8 slide 66-69)."""
        aes, mac = generate_session_keys()
        plaintext = b"same input"
        a = encrypt_payload(plaintext, aes, mac)
        b = encrypt_payload(plaintext, aes, mac)
        self.assertNotEqual(a, b, "IV must be fresh per payload")

    def test_tamper_detected(self):
        aes, mac = generate_session_keys()
        blob = bytearray(encrypt_payload(b"original", aes, mac))
        # Flip one bit in the ciphertext region
        blob[20] ^= 0x01
        with self.assertRaises(ValueError):
            decrypt_payload(bytes(blob), aes, mac)

    def test_wrong_key_rejected(self):
        aes1, mac1 = generate_session_keys()
        aes2, mac2 = generate_session_keys()
        blob = encrypt_payload(b"secret", aes1, mac1)
        with self.assertRaises(ValueError):
            decrypt_payload(blob, aes2, mac2)


class TestSHA256(unittest.TestCase):
    """File integrity verification (Báo cáo §8.3)."""

    def test_sha256_bytes_deterministic(self):
        self.assertEqual(sha256_bytes(b"hello"),
                         "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")

    def test_sha256_file_round_trip(self):
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"file content for hashing")
            tmp_path = tmp.name
        try:
            expected = sha256_bytes(b"file content for hashing")
            self.assertEqual(sha256_file(tmp_path), expected)
        finally:
            os.remove(tmp_path)

    def test_sha256_changes_with_content(self):
        with tempfile.NamedTemporaryFile(delete=False) as t1:
            t1.write(b"version A"); p1 = t1.name
        with tempfile.NamedTemporaryFile(delete=False) as t2:
            t2.write(b"version B"); p2 = t2.name
        try:
            self.assertNotEqual(sha256_file(p1), sha256_file(p2))
        finally:
            os.remove(p1); os.remove(p2)


if __name__ == "__main__":
    unittest.main()
