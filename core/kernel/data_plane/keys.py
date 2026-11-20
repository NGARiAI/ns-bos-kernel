"""Sources for the data plane's Fernet master key.

A provider returns the 44-byte urlsafe-base64 Fernet key and reports how that
key is held. Providers never log, print or raise with key bytes. A provider that
cannot produce the key raises KeyProviderError and the data plane stops: there
is no fallback to another provider, and no fresh key when encrypted data exists.
"""

import contextlib
import errno
import logging
import os
import secrets
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping
from pathlib import Path

from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)

PROVIDER_ENV = "NGARI_KEY_PROVIDER"
SEALED_NAME = "master.key.sealed"  # the tpm2 provider's file, beside master.key
DEFAULT_PROVIDER = "file"

# link(2) errors on filesystems that cannot hard-link (FAT, some network mounts).
_NO_HARD_LINKS = {errno.EPERM, errno.ENOTSUP, errno.EOPNOTSUPP, errno.ENOSYS}


class KeyProviderError(Exception):
    """The master key could not be loaded, created or verified."""


class KeyNotProvisionedError(KeyProviderError):
    """No key exists and the caller did not allow creating one."""


def validate_key(key: bytes) -> bytes:
    """Return key if Fernet accepts it. The error never contains the key."""
    try:
        Fernet(key)
    except (ValueError, TypeError):
        got = f"{len(key)} bytes" if isinstance(key, bytes) else type(key).__name__
        raise KeyProviderError(
            f"master key is not a valid Fernet key (got {got})"
        ) from None
    return key


def make_private_dir(path: Path) -> None:
    """Create path, and every missing directory above it, owner-only (0700).
    mkdir's mode covers only the last directory; the ones parents=True makes
    get the umask's, 0755 as a rule, and the store's own directories must
    not be listable by other users. Directories that exist are left as
    they are."""
    missing = []
    path = Path(path)
    while not path.exists() and path != path.parent:
        missing.append(path)
        path = path.parent
    for directory in reversed(missing):
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError:
            pass
        else:
            os.chmod(directory, 0o700)  # whatever the umask took away


def publish_new_file(path: Path, data: bytes) -> bool:
    """Make path appear holding data, complete or not at all (mode 0600).

    The data is written and synced under a private temporary name in the same
    directory, then hard-linked to path. The link fails if another process got
    there first, and that process's file is left alone. A reader never sees an
    empty or partial file, and a crash leaves nothing at path. Returns True when
    this call created the file and False when it already existed.
    """
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        _write_synced(fd, data)
        try:
            os.link(tmp, path)
        except FileExistsError:
            return False
        except OSError as exc:
            if exc.errno not in _NO_HARD_LINKS:
                raise
            return _create_in_place(path, data)
        # The file is published now and another process may already be using
        # it, so a failed sync is reported but never undoes the link.
        _sync_directory(path.parent)
        return True
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)


def _create_in_place(path: Path, data: bytes) -> bool:
    """Exclusive create for filesystems without hard links. A concurrent
    reader can see the file before the data is in it, so a partial file this
    call made is removed on failure."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return False
    try:
        _write_synced(fd, data)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(path)
        raise
    return True


def _write_synced(fd: int, data: bytes) -> None:
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def _sync_directory(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class KeyProvider(ABC):
    name: str

    @abstractmethod
    def load_or_create(self, *, may_create: bool = True) -> bytes:
        """Return the Fernet key.

        With may_create False, raise KeyNotProvisionedError rather than create
        a key. Every other failure raises KeyProviderError.
        """

    @abstractmethod
    def describe(self) -> dict:
        """Facts about how the key is held, measured now. Never the key.

        Always holds "provider" (str), "hardware_bound" (bool) and "ok" (bool,
        True only when the key is held as this provider promises).
        """


class FileKeyProvider(KeyProvider):
    """Fernet key in a file readable only by its owner (mode 0600)."""

    name = "file"

    def __init__(self, key_file: Path):
        self.key_file = Path(key_file)

    def __repr__(self) -> str:
        return f"FileKeyProvider({str(self.key_file)!r})"

    def load_or_create(self, *, may_create: bool = True) -> bytes:
        try:
            os.chmod(self.key_file.parent, 0o700)
            if not self.key_file.exists():
                if not may_create:
                    raise KeyNotProvisionedError(f"no key file at {self.key_file}")
                sealed = self.key_file.with_name(SEALED_NAME)
                if sealed.exists():
                    # The store runs on the tpm2 provider. A new plaintext key
                    # here would encrypt new data under a key the sealed one
                    # cannot read, with nothing to tell the two apart later.
                    raise KeyProviderError(
                        f"a sealed key exists at {sealed} and no plaintext key at "
                        f"{self.key_file}. Refusing to create a second key. Start with "
                        f"{PROVIDER_ENV}=tpm2, or restore the key from a recovery "
                        "bundle first."
                    )
                publish_new_file(self.key_file, Fernet.generate_key())
            if self.key_file.stat().st_mode & 0o077:
                logger.warning("Key file permissions too open - tightening to 0600")
                os.chmod(self.key_file, 0o600)
            return self.key_file.read_bytes()
        except OSError as exc:
            raise KeyProviderError(
                f"cannot use key file {self.key_file}: {exc.strerror}"
            ) from None

    def describe(self) -> dict:
        try:
            mode = self.key_file.stat().st_mode & 0o777
        except OSError:
            mode = None
        return {
            "provider": self.name,
            "hardware_bound": False,
            "at_rest": "plaintext file, protected by filesystem permissions",
            "key_file": str(self.key_file),
            "key_file_mode": oct(mode) if mode is not None else None,
            "ok": mode == 0o600,
        }


def _tpm2(keys_dir: Path, environ: Mapping[str, str]) -> KeyProvider:
    from .tpm import TPMKeyProvider  # imported here: only tpm2 users need it

    return TPMKeyProvider.from_env(keys_dir, environ)


_FACTORIES: dict[str, Callable[[Path, Mapping[str, str]], KeyProvider]] = {
    "file": lambda keys_dir, environ: FileKeyProvider(keys_dir / "master.key"),
    "tpm2": _tpm2,
}


def create_provider(
    name: str | None, keys_dir: Path, environ: Mapping[str, str] | None = None
) -> KeyProvider:
    """Build the named provider (default "file"); unknown names raise."""
    wanted = (name or DEFAULT_PROVIDER).strip().lower()
    factory = _FACTORIES.get(wanted)
    if factory is None:
        raise KeyProviderError(
            f"unknown key provider {wanted!r}; known: {', '.join(sorted(_FACTORIES))}"
        )
    return factory(Path(keys_dir), os.environ if environ is None else environ)


def provider_from_env(
    keys_dir: Path, environ: Mapping[str, str] | None = None
) -> KeyProvider:
    env = os.environ if environ is None else environ
    return create_provider(env.get(PROVIDER_ENV), keys_dir, env)
