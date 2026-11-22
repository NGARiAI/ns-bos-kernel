"""Passphrase-wrapped copy of the master key, for when the TPM is gone.

A sealed key cannot be unsealed without the TPM that sealed it. The recovery
bundle holds the Fernet master key, encrypted with a key derived from an
operator passphrase by scrypt (N=2**15, r=8, p=1), in a small JSON file the
operator stores off the machine. A wrong passphrase or an edited bundle fails
closed. Neither the key nor the passphrase is ever logged or put in an error.
"""

import base64
import binascii
import hashlib
import json
import secrets

from cryptography.fernet import Fernet, InvalidToken

from .keys import KeyProviderError, validate_key

FORMAT_VERSION = 1
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
SALT_BYTES = 16
MAXMEM = 64 * 1024 * 1024
MIN_PASSPHRASE = 12


class RecoveryError(KeyProviderError):
    """The bundle could not be made or opened."""


def _derive(passphrase: bytes, salt: bytes, n: int, r: int, p: int) -> Fernet:
    key = hashlib.scrypt(passphrase, salt=salt, n=n, r=r, p=p, maxmem=MAXMEM, dklen=32)
    return Fernet(base64.urlsafe_b64encode(key))


def check_passphrase(passphrase: bytes) -> bytes:
    if len(passphrase) < MIN_PASSPHRASE:
        raise RecoveryError(
            f"the passphrase must be at least {MIN_PASSPHRASE} characters"
        )
    return passphrase


def wrap(master_key: bytes, passphrase: bytes) -> bytes:
    """Bundle bytes for master_key. Verified to open again before returning."""
    validate_key(master_key)
    check_passphrase(passphrase)
    salt = secrets.token_bytes(SALT_BYTES)
    token = _derive(passphrase, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P).encrypt(master_key)
    bundle = {
        "version": FORMAT_VERSION,
        "kdf": {"name": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P},
        "salt": base64.b64encode(salt).decode(),
        "token": token.decode(),
    }
    data = (json.dumps(bundle, sort_keys=True, indent=2) + "\n").encode()
    if unwrap(data, passphrase) != master_key:
        raise RecoveryError("the recovery bundle did not open to the same key")
    return data


def unwrap(data: bytes, passphrase: bytes) -> bytes:
    """The master key in a bundle. Raises RecoveryError on any problem."""
    try:
        bundle = json.loads(data)
        if not isinstance(bundle, dict) or bundle.get("version") != FORMAT_VERSION:
            raise ValueError("unknown format version")
        kdf = bundle["kdf"]
        n, r, p = kdf["n"], kdf["r"], kdf["p"]
        # Bounded so that a crafted bundle cannot demand unbounded memory or time.
        if kdf["name"] != "scrypt" or not all(type(v) is int for v in (n, r, p)):
            raise ValueError("unsupported kdf")
        if not (
            2**14 <= n <= 2**17 and n & (n - 1) == 0 and 1 <= r <= 16 and 1 <= p <= 4
        ):
            raise ValueError("kdf parameters out of range")
        salt = base64.b64decode(bundle["salt"], validate=True)
        token = bundle["token"].encode("ascii")
        if len(salt) < SALT_BYTES:
            raise ValueError("salt too short")
    except (
        ValueError, KeyError, TypeError, AttributeError, binascii.Error, RecursionError,
    ) as exc:  # fmt: skip
        raise RecoveryError(
            f"not a valid recovery bundle ({type(exc).__name__})"
        ) from None
    try:
        key = _derive(passphrase, salt, n, r, p).decrypt(token)
    except (InvalidToken, ValueError):
        raise RecoveryError(
            "the passphrase is wrong or the bundle was changed"
        ) from None
    return validate_key(key)
