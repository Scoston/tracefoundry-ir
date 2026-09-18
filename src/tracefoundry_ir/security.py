"""Canonical serialization, byte integrity, and explicit local trust anchors."""

import base64
import hashlib
import hmac
import json
import os
import secrets
from datetime import UTC, datetime
from pathlib import Path

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


def canonical(value) -> bytes:
    return rfc8785.dumps(value)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(domain: str, body: dict) -> str:
    return sha256(domain.encode() + b"\0" + canonical(body))


def strict_json(data: str | bytes):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError(f"Duplicate JSON field: {key}")
            result[key] = value
        return result

    def invalid(value):
        raise ValueError(f"Non-finite JSON value: {value}")

    return json.loads(data, object_pairs_hook=pairs, parse_constant=invalid)


def secret_write(path: Path, data: bytes, *, replace: bool = False):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not replace:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    else:
        temporary = path.with_name(path.name + "." + secrets.token_hex(8))
        try:
            secret_write(temporary, data)
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
    if os.name != "nt":
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


class Signer:
    def __init__(self, path: Path):
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(
            key.curve, ec.SECP256R1
        ):
            raise ValueError("Expected a P-256 signing key")
        self.key = key
        self.public_pem = key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.key_id = sha256(
            key.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    @classmethod
    def create(cls, path: Path):
        key = ec.generate_private_key(ec.SECP256R1())
        secret_write(
            path,
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        )
        return cls(path)

    def sign(self, domain: str, body: dict) -> dict:
        der = self.key.sign(domain.encode() + b"\0" + canonical(body), ec.ECDSA(hashes.SHA256()))
        r, s = utils.decode_dss_signature(der)
        signature = base64.urlsafe_b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
        return {
            "body": body,
            "key_id": self.key_id,
            "algorithm": "ES256",
            "signature": signature.decode().rstrip("="),
        }


def verify_signature(envelope: dict, domain: str, trusted_pem: bytes) -> bool:
    try:
        public = serialization.load_pem_public_key(trusted_pem)
        if not isinstance(public, ec.EllipticCurvePublicKey) or not isinstance(
            public.curve, ec.SECP256R1
        ):
            return False
        key_id = sha256(
            public.public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
        if envelope["key_id"] != key_id or envelope["algorithm"] != "ES256":
            return False
        raw = base64.b64decode(envelope["signature"] + "==", altchars=b"-_", validate=True)
        if len(raw) != 64:
            return False
        der = utils.encode_dss_signature(
            int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
        )
        public.verify(
            der, domain.encode() + b"\0" + canonical(envelope["body"]), ec.ECDSA(hashes.SHA256())
        )
        return True
    except (ValueError, KeyError, TypeError, InvalidSignature):
        return False


class Vault:
    def __init__(self, path: Path):
        self.aes = AESGCM(path.read_bytes())

    def encrypt(self, data: bytes, binding: str) -> bytes:
        nonce = secrets.token_bytes(12)
        return nonce + self.aes.encrypt(nonce, data, binding.encode())

    def decrypt(self, data: bytes, binding: str) -> bytes:
        return self.aes.decrypt(data[:12], data[12:], binding.encode())


def password_hash(password: str) -> str:
    if not 14 <= len(password) <= 256:
        raise ValueError("Password must contain 14 to 256 characters")
    salt = secrets.token_bytes(32)
    result = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
    return salt.hex() + ":" + result.hex()


def password_matches(password: str, stored: str) -> bool:
    if len(password) > 256:
        return False
    salt, expected = stored.split(":")
    result = hashlib.scrypt(
        password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1, dklen=32
    )
    return hmac.compare_digest(result.hex(), expected)
