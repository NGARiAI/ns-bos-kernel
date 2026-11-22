"""The key for agent state kept outside the data plane (agent registry,
tasks, messages). It is derived from the master key, so whatever holds the
master key (a file, a TPM) holds this one too, and a recovery bundle of the
master key covers agent state with no new custody path.

Nothing here keeps, prints or logs the master key."""

import base64

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# HKDF info strings. Each derivation from the master key has its own, so the
# state key, the audit MAC key and the data plane's own Fernet key never meet.
STATE_INFO = b"ngari-state-v1"
STATE_ID_INFO = b"ngari-key-id-v1"


def _derive(master_key: bytes, info: bytes, length: int) -> bytes:
    raw = base64.urlsafe_b64decode(master_key)
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(
        raw
    )


class StateCipher:
    """Encrypts agent state under the derived key. key_id names the master key
    the state belongs to (16 derived bytes in hex) so a file sealed under
    another key is recognised before anything tries to open it."""

    def __init__(self, master_key: bytes):
        self._fernet = Fernet(
            base64.urlsafe_b64encode(_derive(master_key, STATE_INFO, 32))
        )
        self.key_id = _derive(master_key, STATE_ID_INFO, 16).hex()

    def encrypt(self, data: bytes) -> str:
        return self._fernet.encrypt(data).decode("ascii")

    def decrypt(self, token: str) -> bytes:
        """Decrypt token. Raises cryptography.fernet.InvalidToken if damaged."""
        return self._fernet.decrypt(token)

    def __repr__(self) -> str:
        return f"StateCipher(key_id={self.key_id})"
