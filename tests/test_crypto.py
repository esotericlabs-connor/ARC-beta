from __future__ import annotations

import hmac
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.crypto import (
    AlgorithmMismatchError,
    EncryptedPacket,
    HandshakeMessage,
    HybridPQCEncryptor,
    PublicBundle,
    SessionKeyError,
    SignatureVerificationError,
)


class DummyProvider:
    """Deterministic provider used to exercise the hybrid encryptor logic."""

    kem_algorithm = "dummy-kyber"
    signature_algorithm = "dummy-dilithium"

    def __init__(self) -> None:
        self._signature_secrets: dict[bytes, bytes] = {}

    # Kyber-style interface -------------------------------------------------
    def generate_kem_keypair(self) -> tuple[bytes, bytes]:
        secret = os.urandom(32)
        return secret, secret

    def kem_encapsulate(self, peer_public_key: bytes) -> tuple[bytes, bytes]:
        ciphertext = peer_public_key[::-1]
        shared_secret = self._derive_shared_secret(peer_public_key)
        return ciphertext, shared_secret

    def kem_decapsulate(self, ciphertext: bytes, private_key: bytes) -> bytes:
        peer_public_key = ciphertext[::-1]
        return self._derive_shared_secret(peer_public_key)

    # Dilithium-style interface --------------------------------------------
    def generate_signature_keypair(self) -> tuple[bytes, bytes]:
        private = os.urandom(32)
        public = self._hash(private)
        self._signature_secrets[public] = private
        return public, private

    def sign(self, message: bytes, private_key: bytes) -> bytes:
        return hmac.new(private_key, message, digestmod="sha3_256").digest()

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> None:
        try:
            private_key = self._signature_secrets[public_key]
        except KeyError as exc:
            raise SignatureVerificationError("Unknown signature key") from exc
        expected = hmac.new(private_key, message, digestmod="sha3_256").digest()
        if not hmac.compare_digest(expected, signature):
            raise SignatureVerificationError("Signature mismatch")

    # Helpers ----------------------------------------------------------------
    @staticmethod
    def _derive_shared_secret(public_key: bytes) -> bytes:
        return hmac.new(public_key, b"arc", digestmod="sha3_256").digest()

    @staticmethod
    def _hash(value: bytes) -> bytes:
        return hmac.new(b"dummy", value, digestmod="sha3_256").digest()


def test_handshake_and_encryption_roundtrip() -> None:
    provider = DummyProvider()
    alice = HybridPQCEncryptor(provider=provider)
    bob = HybridPQCEncryptor(provider=provider)

    alice_bundle = alice.public_bundle()
    bob_bundle = bob.public_bundle()

    handshake = alice.initiate_handshake(bob_bundle)
    bob.receive_handshake(handshake, alice_bundle)

    assert alice.has_session() is True
    assert bob.has_session() is True

    packet = alice.encrypt(b"confidential payload", aad=b"meta")
    assert isinstance(packet, EncryptedPacket)

    recovered = bob.decrypt(packet, aad=b"meta")
    assert recovered == b"confidential payload"


def test_encrypt_without_handshake_raises() -> None:
    encryptor = HybridPQCEncryptor(provider=DummyProvider())
    with pytest.raises(SessionKeyError):
        encryptor.encrypt(b"test")


def test_signature_tampering_detected() -> None:
    provider = DummyProvider()
    alice = HybridPQCEncryptor(provider=provider)
    bob = HybridPQCEncryptor(provider=provider)

    handshake = alice.initiate_handshake(bob.public_bundle())
    tampered = HandshakeMessage(
        ciphertext=handshake.ciphertext,
        signature=handshake.signature[:-1] + bytes([handshake.signature[-1] ^ 0xFF]),
        salt=handshake.salt,
        kem_algorithm=handshake.kem_algorithm,
        signature_algorithm=handshake.signature_algorithm,
        initiator_signature_key=handshake.initiator_signature_key,
    )

    with pytest.raises(SignatureVerificationError):
        bob.receive_handshake(tampered, alice.public_bundle())


def test_algorithm_mismatch_detected() -> None:
    provider = DummyProvider()
    alice = HybridPQCEncryptor(provider=provider)
    bob = HybridPQCEncryptor(provider=provider)

    bundle = PublicBundle(
        kem_public_key=b"wrong",
        signature_public_key=b"wrong",
        kem_algorithm="other-kyber",
        signature_algorithm=provider.signature_algorithm,
    )

    with pytest.raises(AlgorithmMismatchError):
        alice.initiate_handshake(bundle)

    # Ensure receive also guards algorithm mismatches.
    handshake = alice.initiate_handshake(bob.public_bundle())
    mismatch_bundle = PublicBundle(
        kem_public_key=b"same",
        signature_public_key=handshake.initiator_signature_key,
        kem_algorithm=provider.kem_algorithm,
        signature_algorithm="other-dilithium",
    )
    with pytest.raises(AlgorithmMismatchError):
        bob.receive_handshake(handshake, mismatch_bundle)