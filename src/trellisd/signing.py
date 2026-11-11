"""Ed25519 signing for grant entries and ledger checkpoints.

The private key stays in a file only Trellis reads (created with mode 0600 if missing).
The public key is recorded in the database and in every checkpoint, so anyone holding a
checkpoint can check it without the private key.
"""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

DEFAULT_KEY_PATH = "trellisd-signing.key"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def key_id_for(public_key: str) -> str:
    return "k-" + hashlib.sha256(public_key.encode("ascii")).hexdigest()[:12]


class Signer:
    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._key = private_key
        raw = private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.public_key = _b64(raw)
        self.key_id = key_id_for(self.public_key)

    @classmethod
    def generate(cls) -> Signer:
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def load_or_create(cls, path: str | Path = DEFAULT_KEY_PATH) -> Signer:
        p = Path(path)
        if p.exists():
            key = serialization.load_pem_private_key(p.read_bytes(), password=None)
            if not isinstance(key, Ed25519PrivateKey):
                raise ValueError(f"{p} is not an Ed25519 private key")
            return cls(key)
        signer = cls.generate()
        pem = signer._key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(pem)
        return signer

    def sign(self, message: str) -> str:
        return _b64(self._key.sign(message.encode("utf-8")))


def verify_signature(public_key: str, message: str, signature: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(_unb64(public_key)).verify(
            _unb64(signature), message.encode("utf-8")
        )
    except (InvalidSignature, ValueError):
        return False
    return True
