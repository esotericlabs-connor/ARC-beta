"""Hybrid post-quantum + symmetric encryption utilities for ARC."""
from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from typing import Optional, Protocol, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class PQCryptoUnavailable(RuntimeError):
    """Raised when no compatible post-quantum provider is available."""


class HandshakeVerificationError(RuntimeError):
    """Base error for handshake verification problems."""


class SignatureVerificationError(HandshakeVerificationError):
    """Raised when Dilithium signature validation fails."""


class AlgorithmMismatchError(HandshakeVerificationError):
    """Raised when handshake metadata does not match the local provider."""


class SessionKeyError(RuntimeError):
    """Raised when a session key is not available."""


@dataclass(frozen=True)
class PublicBundle:
    """Public material distributed during pre-flight negotiation."""

    kem_public_key: bytes
    signature_public_key: bytes
    kem_algorithm: str
    signature_algorithm: str

    def as_dict(self) -> dict[str, str]:
        """Render the bundle as base64 strings for JSON-friendly transit."""

        return {
            "kem_public_key": base64.b64encode(self.kem_public_key).decode("ascii"),
            "signature_public_key": base64.b64encode(self.signature_public_key).decode("ascii"),
            "kem_algorithm": self.kem_algorithm,
            "signature_algorithm": self.signature_algorithm,
        }


@dataclass(frozen=True)
class HandshakeMessage:
    """Serialized payload produced by :meth:`HybridPQCEncryptor.initiate_handshake`."""

    ciphertext: bytes
    signature: bytes
    salt: bytes
    kem_algorithm: str
    signature_algorithm: str
    initiator_signature_key: bytes

    def as_dict(self) -> dict[str, str]:
        """Render the handshake packet as JSON-safe strings."""

        return {
            "ciphertext": base64.b64encode(self.ciphertext).decode("ascii"),
            "signature": base64.b64encode(self.signature).decode("ascii"),
            "salt": base64.b64encode(self.salt).decode("ascii"),
            "kem_algorithm": self.kem_algorithm,
            "signature_algorithm": self.signature_algorithm,
            "initiator_signature_key": base64.b64encode(self.initiator_signature_key).decode("ascii"),
        }


@dataclass(frozen=True)
class EncryptedPacket:
    """AES-256-GCM encrypted payload."""

    nonce: bytes
    ciphertext: bytes

    def as_dict(self) -> dict[str, str]:
        return {
            "nonce": base64.b64encode(self.nonce).decode("ascii"),
            "ciphertext": base64.b64encode(self.ciphertext).decode("ascii"),
        }


class PQCProvider(Protocol):
    """Abstract interface for hybrid PQC providers."""

    kem_algorithm: str
    signature_algorithm: str

    def generate_kem_keypair(self) -> Tuple[bytes, bytes]:
        ...

    def kem_encapsulate(self, peer_public_key: bytes) -> Tuple[bytes, bytes]:
        ...

    def kem_decapsulate(self, ciphertext: bytes, private_key: bytes) -> bytes:
        ...

    def generate_signature_keypair(self) -> Tuple[bytes, bytes]:
        ...

    def sign(self, message: bytes, private_key: bytes) -> bytes:
        ...

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> None:
        ...


def _load_pqcrypto_provider() -> Optional["PQCryptoProvider"]:
    try:
        return PQCryptoProvider()
    except (ImportError, RuntimeError):
        return None


class PQCryptoProvider:
    """Adapter over the :mod:`pqcrypto` reference implementations."""

    def __init__(self, kem: str = "kyber768", signature: str = "dilithium3") -> None:
        try:
            import importlib

            kem_module = importlib.import_module(f"pqcrypto.kem.{kem}")
            signature_module = importlib.import_module(f"pqcrypto.sign.{signature}")
        except ImportError as exc:
            raise ImportError("pqcrypto provider not available") from exc

        self._kem_module = kem_module
        self._signature_module = signature_module
        self.kem_algorithm = kem
        self.signature_algorithm = signature

    def generate_kem_keypair(self) -> Tuple[bytes, bytes]:
        return self._kem_module.generate_keypair()

    def kem_encapsulate(self, peer_public_key: bytes) -> Tuple[bytes, bytes]:
        ciphertext, shared_secret = self._kem_module.encrypt(peer_public_key)
        return ciphertext, shared_secret

    def kem_decapsulate(self, ciphertext: bytes, private_key: bytes) -> bytes:
        return self._kem_module.decrypt(ciphertext, private_key)

    def generate_signature_keypair(self) -> Tuple[bytes, bytes]:
        return self._signature_module.generate_keypair()

    def sign(self, message: bytes, private_key: bytes) -> bytes:
        if hasattr(self._signature_module, "sign_signature"):
            return self._signature_module.sign_signature(message, private_key)
        return self._signature_module.sign(message, private_key)

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> None:
        try:
            if hasattr(self._signature_module, "verify_signature"):
                self._signature_module.verify_signature(signature, message, public_key)
                return
            opened = self._signature_module.open(signature, public_key)
            if opened != message:
                raise SignatureVerificationError("Signed payload did not match")
        except Exception as exc:  # noqa: BLE001 - propagate as crypto failure
            raise SignatureVerificationError("Dilithium signature verification failed") from exc


def select_default_provider() -> PQCProvider:
    provider = _load_pqcrypto_provider()
    if provider is None:
        raise PQCryptoUnavailable(
            "No post-quantum provider found. Install 'pqcrypto' to enable Kyber/Dilithium support."
        )
    return provider


class HybridPQCEncryptor:
    """High-level Kyber + Dilithium hybrid session manager with AES-256-GCM."""

    def __init__(self, provider: Optional[PQCProvider] = None) -> None:
        self.provider = provider or select_default_provider()
        self._kem_public_key, self._kem_private_key = self.provider.generate_kem_keypair()
        self._signature_public_key, self._signature_private_key = (
            self.provider.generate_signature_keypair()
        )
        self._session_key: Optional[bytes] = None
        self._peer_signature_key: Optional[bytes] = None

    @property
    def kem_algorithm(self) -> str:
        return self.provider.kem_algorithm

    @property
    def signature_algorithm(self) -> str:
        return self.provider.signature_algorithm

    @property
    def signature_public_key(self) -> bytes:
        return self._signature_public_key

    def public_bundle(self) -> PublicBundle:
        return PublicBundle(
            kem_public_key=self._kem_public_key,
            signature_public_key=self._signature_public_key,
            kem_algorithm=self.kem_algorithm,
            signature_algorithm=self.signature_algorithm,
        )

    def initiate_handshake(self, peer_bundle: PublicBundle, *, salt: Optional[bytes] = None) -> HandshakeMessage:
        self._validate_algorithms(peer_bundle)
        salt = salt or os.urandom(16)
        ciphertext, shared_secret = self.provider.kem_encapsulate(peer_bundle.kem_public_key)
        payload = self._handshake_payload(
            initiator_signature_key=self._signature_public_key,
            recipient_signature_key=peer_bundle.signature_public_key,
            ciphertext=ciphertext,
            salt=salt,
        )
        signature = self.provider.sign(payload, self._signature_private_key)
        self._session_key = self._derive_session_key(shared_secret, peer_bundle.signature_public_key, salt)
        self._peer_signature_key = peer_bundle.signature_public_key
        return HandshakeMessage(
            ciphertext=ciphertext,
            signature=signature,
            salt=salt,
            kem_algorithm=self.kem_algorithm,
            signature_algorithm=self.signature_algorithm,
            initiator_signature_key=self._signature_public_key,
        )

    def receive_handshake(self, handshake: HandshakeMessage, peer_bundle: PublicBundle) -> None:
        self._validate_algorithms(peer_bundle)
        if handshake.kem_algorithm != self.kem_algorithm or handshake.signature_algorithm != self.signature_algorithm:
            raise AlgorithmMismatchError("Handshake algorithms do not match local configuration")
        if handshake.initiator_signature_key != peer_bundle.signature_public_key:
            raise SignatureVerificationError("Initiator signature key mismatch")
        payload = self._handshake_payload(
            initiator_signature_key=peer_bundle.signature_public_key,
            recipient_signature_key=self._signature_public_key,
            ciphertext=handshake.ciphertext,
            salt=handshake.salt,
        )
        self.provider.verify(payload, handshake.signature, peer_bundle.signature_public_key)
        shared_secret = self.provider.kem_decapsulate(handshake.ciphertext, self._kem_private_key)
        self._session_key = self._derive_session_key(shared_secret, peer_bundle.signature_public_key, handshake.salt)
        self._peer_signature_key = peer_bundle.signature_public_key

    def encrypt(self, plaintext: bytes, *, aad: Optional[bytes] = None) -> EncryptedPacket:
        key = self._require_session_key()
        nonce = os.urandom(12)
        cipher = AESGCM(key)
        ciphertext = cipher.encrypt(nonce, plaintext, aad)
        return EncryptedPacket(nonce=nonce, ciphertext=ciphertext)

    def decrypt(self, packet: EncryptedPacket, *, aad: Optional[bytes] = None) -> bytes:
        key = self._require_session_key()
        cipher = AESGCM(key)
        return cipher.decrypt(packet.nonce, packet.ciphertext, aad)

    def clear_session(self) -> None:
        self._session_key = None
        self._peer_signature_key = None

    def has_session(self) -> bool:
        return self._session_key is not None

    def _require_session_key(self) -> bytes:
        if self._session_key is None:
            raise SessionKeyError("Session key is not established. Complete a handshake first.")
        return self._session_key

    def _validate_algorithms(self, peer_bundle: PublicBundle) -> None:
        if peer_bundle.kem_algorithm != self.kem_algorithm:
            raise AlgorithmMismatchError("Kyber algorithm mismatch")
        if peer_bundle.signature_algorithm != self.signature_algorithm:
            raise AlgorithmMismatchError("Dilithium algorithm mismatch")

    def _derive_session_key(self, shared_secret: bytes, peer_signature_key: bytes, salt: bytes) -> bytes:
        ordered_keys = sorted([self._signature_public_key, peer_signature_key])
        info = b"ARC-HYBRID-PQC|" + self.kem_algorithm.encode() + b"|" + self.signature_algorithm.encode()
        info += b"|" + ordered_keys[0] + b"|" + ordered_keys[1]
        hkdf = HKDF(
            algorithm=hashes.SHA3_256(),
            length=32,
            salt=salt,
            info=info,
        )
        return hkdf.derive(shared_secret)

    @staticmethod
    def _handshake_payload(
        *,
        initiator_signature_key: bytes,
        recipient_signature_key: bytes,
        ciphertext: bytes,
        salt: bytes,
    ) -> bytes:
        return b"|".join(
            [
                b"ARC-HANDSHAKE",
                initiator_signature_key,
                recipient_signature_key,
                ciphertext,
                salt,
            ]
        )


__all__ = [
    "AlgorithmMismatchError",
    "EncryptedPacket",
    "HandshakeMessage",
    "HandshakeVerificationError",
    "HybridPQCEncryptor",
    "PQCryptoProvider",
    "PQCryptoUnavailable",
    "PublicBundle",
    "SessionKeyError",
    "SignatureVerificationError",
]