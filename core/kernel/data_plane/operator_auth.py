"""Operator check with a PIV/CAC card before a key command (docs/PIV_CAC.md).

The card signs a challenge bound to the command, the data directory and the
certificate. The signature is verified with a certificate pinned in
sovereign/operators/, never with the copy the card presents. The card is
driven through OpenSC's pkcs11-tool; the PIN reaches it only through a
variable in the child process's environment, never argv.

A pinned certificate may have a named operator beside it, <user>.json with
the user id and printed name (`keys pin-operator`), which the gate then
records in place of the card's fingerprint.
"""

import ctypes.util
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID

from .keys import KeyProviderError
from .redact import redact

AUTH_ENV = "NGARI_OPERATOR_AUTH"
MODULE_ENV = "NGARI_PKCS11_MODULE"
TOKEN_ENV = "NGARI_PKCS11_TOKEN"
OBJECT_ID_ENV = "NGARI_PKCS11_KEY_ID"
DEFAULT_KEY_ID = "01"  # PIV slot 9A, PIV Authentication, in OpenSC
CHALLENGE_LABEL = b"ngari-operator-auth-v1"
# A different label, so a signature made to pass the gate can never stand in
# for a signature on a record, or the other way round.
ESIGN_LABEL = b"ngari-esignature-v1"
MANIFEST_LABEL = b"ngari-agent-manifest-v1"  # an agent manifest (agent_manifest.py)
CARD_CHECK = "keys card-check"  # the command a card-check signature is bound to
TIMEOUT = 60.0  # a card reader can be slow, and the user may be typing
_PIN_VAR = "NGARI_CARD_PIN"
PCSC_SOCKET = "/run/pcscd/pcscd.comm"  # pcsc-lite's default
PCSCD_PATHS = ("/usr/sbin/pcscd",)  # where Debian and Ubuntu install it
IDENTITY_VERSION = 1
NAME_MAX = 128  # characters in a printed name
# A user id is a file name in operators/ and an audit actor: no path
# characters, no leading dot or dash.
_USER_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", re.ASCII)
_FINGERPRINT = re.compile(r"[0-9a-f]{64}", re.ASCII)
_MODULE_CANDIDATES = (
    "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
    "/usr/lib/aarch64-linux-gnu/opensc-pkcs11.so",
    "/usr/lib64/opensc-pkcs11.so",
    "/usr/lib/opensc-pkcs11.so",
)


class OperatorAuthError(KeyProviderError):
    """The operator could not be authenticated. Carries a short reason."""

    def __init__(self, message: str, reason: str, fingerprint: str = "unknown"):
        super().__init__(message)
        self.reason = reason
        self.fingerprint = fingerprint


def default_module() -> str:
    for path in _MODULE_CANDIDATES:
        if Path(path).exists():
            return path
    return _MODULE_CANDIDATES[0]


def load_pinned(operators_dir: Path) -> dict[str, x509.Certificate]:
    """Pinned certificates by SHA-256 fingerprint (hex). PEM or DER files."""
    pinned = {}
    if not operators_dir.is_dir():
        return pinned
    for path in sorted(operators_dir.iterdir()):
        if path.suffix.lower() not in (".pem", ".crt", ".cer", ".der"):
            continue
        data = path.read_bytes()
        try:
            certs = (
                x509.load_pem_x509_certificates(data)  # every block in the file
                if b"-----BEGIN" in data
                else [x509.load_der_x509_certificate(data)]
            )
        except ValueError:
            raise OperatorAuthError(
                f"{path} is not a certificate", "bad pinned certificate"
            ) from None
        for cert in certs:
            pinned[cert.fingerprint(hashes.SHA256()).hex()] = cert
    return pinned


def user_id_problem(user) -> str | None:
    """Why user cannot be an operator's user id, or None."""
    if not isinstance(user, str) or not _USER_ID.fullmatch(user):
        return (
            "a user id is 1 to 64 letters, digits or the characters . _ -, "
            "starting with a letter or digit"
        )
    if redact(user) != user:
        return (
            "the user id looks like personal data and would be masked in the audit log"
        )
    return None


def name_problem(name) -> str | None:
    """Why name cannot be an operator's printed name, or None. The name is
    what an audit entry and a signature show, so it must reach the audit log
    unchanged: PII redaction would replace an email or a number in it."""
    if not isinstance(name, str) or not name.strip():
        return "the printed name is empty"
    if name != name.strip() or len(name) > NAME_MAX:
        return f"the printed name has spaces at an end or is over {NAME_MAX} characters"
    if not name.isprintable():
        return "the printed name holds a control character"
    if redact(name) != name:
        return (
            f"the printed name {name!r} would be masked by PII redaction in the "
            f"audit log as {redact(name)!r}; give it with --name"
        )
    return None


def identity_bytes(
    user: str, name: str, fingerprint: str, person: str | None = None
) -> bytes:
    """An operator file. person, for a reissued card, is the user id this
    person first had: the new id carries it, so the two are one individual."""
    record = {
        "version": IDENTITY_VERSION,
        "user": user,
        "name": name,
        "fingerprint": fingerprint,
    }
    if person is not None:
        record["person"] = person
    return (json.dumps(record, indent=2, sort_keys=True) + "\n").encode()


def _identity(path: Path) -> dict:
    """The identity in path, or OperatorAuthError saying what is wrong."""

    def bad(why: str) -> OperatorAuthError:
        return OperatorAuthError(f"{path} {why}", "bad operator file")

    try:
        record = json.loads(path.read_bytes())
    except OSError as exc:
        raise bad(f"cannot be read ({exc.strerror})") from None
    except (ValueError, RecursionError):
        raise bad("is not JSON") from None
    if not isinstance(record, dict) or set(record) - {"person"} != {
        "version", "user", "name", "fingerprint",
    }:  # fmt: skip
        raise bad(
            "must hold exactly version, user, name and fingerprint, and person or not"
        )
    if "person" in record and user_id_problem(record["person"]):
        raise bad(f"names person {record['person']!r}, which is not a user id")
    if type(record["version"]) is not int or record["version"] != IDENTITY_VERSION:
        raise bad(f"has version {record['version']!r}, not {IDENTITY_VERSION}")
    for problem in (user_id_problem(record["user"]), name_problem(record["name"])):
        if problem:
            raise bad(f"is not valid: {problem}")
    if record["user"] != path.stem:
        raise bad(
            f"names user {record['user']!r}; the file must be {record['user']}.json"
        )
    fp = record["fingerprint"]
    if not isinstance(fp, str) or not _FINGERPRINT.fullmatch(fp):
        raise bad("has no SHA-256 certificate fingerprint (64 lowercase hex)")
    return record


def load_identities(operators_dir: Path) -> dict[str, dict]:
    """Named operators by certificate fingerprint: {"user", "name"} from each
    <user>.json in operators_dir. A file that is unreadable or not a valid
    identity, or two files naming one certificate, raise OperatorAuthError,
    so the gate fails closed rather than record a card without its name. A
    file whose certificate is not pinned names nobody who can pass."""
    identities: dict[str, dict] = {}
    if not operators_dir.is_dir():
        return identities
    for path in sorted(operators_dir.iterdir()):
        # Exactly <user>.json: with jdoe.JSON read too, two files could both
        # name jdoe, since a file must be named after its user.
        if path.suffix != ".json" or path.name.startswith("."):
            continue
        record = _identity(path)
        fp = record["fingerprint"]
        if fp in identities:
            raise OperatorAuthError(
                f"{path} and {identities[fp]['user']}.json name the same "
                f"certificate {fp[:16]}",
                "bad operator file",
            )
        identities[fp] = {"user": record["user"], "name": record["name"]}
        if "person" in record:
            identities[fp]["person"] = record["person"]
    return identities


def challenge(command: str, store: Path, fingerprint: str, nonce: bytes) -> bytes:
    return b"\0".join(
        (
            CHALLENGE_LABEL,
            command.encode(),
            str(store).encode(),
            fingerprint.encode(),
            nonce,
        )
    )


def esign_message(
    record: str,
    meaning: str,
    user: str,
    name: str,
    fingerprint: str,
    signed_at: str,
    nonce: str,
) -> bytes:
    """What the card signs for an electronic signature: the record's SHA-256
    (hex), the meaning, the signer's user id and printed name, the
    certificate fingerprint, the UTC time and a nonce. None of these can hold
    a NUL byte, so the fields cannot run into each other."""
    fields = (record, meaning, user, name, fingerprint, signed_at, nonce)
    return b"\0".join((ESIGN_LABEL, *(f.encode() for f in fields)))


def card_problem(module: str, output: str) -> str | None:
    """Why pkcs11-tool could not reach a card, from its output and this
    machine, or None. Looks at files and the library search path only."""
    if "Failed to load pkcs11 module" in output:
        if Path(module).exists():
            return None
        return (
            f"the PKCS#11 module {module} does not exist (Debian and Ubuntu "
            f"package: opensc-pkcs11; or set {MODULE_ENV})"
        )
    if "C_Initialize failed" in output and "opensc" in Path(module).name:
        # OpenSC loads libpcsclite and talks to pcscd; without either it
        # fails to initialise with only CKR_GENERAL_ERROR.
        if ctypes.util.find_library("pcsclite") is None:
            missing = "the PC/SC library is not installed (apt install pcscd)"
        elif not (shutil.which("pcscd") or any(Path(p).exists() for p in PCSCD_PATHS)):
            missing = "pcscd is not installed (apt install pcscd)"
        else:
            socket = os.environ.get("PCSCLITE_CSOCK_NAME") or PCSC_SOCKET
            if Path(socket).exists():
                return None
            missing = (
                f"pcscd is not running ({socket} is missing; "
                "systemctl start pcscd.socket)"
            )
        return f"OpenSC cannot reach a card reader: {missing}"
    if "No slots." in output or "No slot with a token was found." in output:
        return (
            "no card was found: check that the reader is connected (pcsc_scan "
            "lists it) and the card is inserted"
        )
    if "CKR_PIN_LOCKED" in output:
        return "the card's PIN is blocked; unblock it with the PUK or have it reissued"
    return None


def _check_validity(cert: x509.Certificate, fp: str) -> None:
    """Refuse a certificate outside its dates, saying which way and what this
    machine's clock reads: on a board with no real-time clock and no network
    time, a wrong clock is the likelier cause."""
    now = datetime.now(timezone.utc)
    start, end = cert.not_valid_before_utc, cert.not_valid_after_utc
    if start <= now <= end:
        return
    dates = f"valid {start:%Y-%m-%d} to {end:%Y-%m-%d}; this machine's clock reads {now:%Y-%m-%d %H:%M} UTC"
    if now < start:
        raise OperatorAuthError(
            f"certificate {fp[:16]} is not valid yet ({dates}). If the clock is "
            "wrong, set it: a board without a real-time clock can start from an old time",
            "not yet valid",
            fp,
        )
    raise OperatorAuthError(
        f"certificate {fp[:16]} has expired ({dates})", "expired", fp
    )


# Keys a certificate may hold (FIPS 186-5; PIV cards use P-256, P-384 and
# RSA-2048). Anything else is refused wherever a certificate is used.
CURVES = ("secp256r1", "secp384r1", "secp521r1")
RSA_MIN_BITS = 2048
RSA_MIN_EXPONENT = 65537
# FIPS 186-5: 2^16 < e < 2^256. A huge exponent admits forgery: with
# e = 1 + lambda(n), s^e = s mod n, and any padded message is a signature.
RSA_EXPONENT_LIMIT = 2**256


def key_problem(cert: x509.Certificate) -> str | None:
    """Why the certificate's key is not accepted, or None."""
    try:
        key = cert.public_key()
    except (ValueError, UnsupportedAlgorithm):
        return (
            "a key that cannot be read (an unknown curve, explicit curve "
            "parameters or an even RSA exponent)"
        )
    if isinstance(key, ec.EllipticCurvePublicKey):
        if key.curve.name not in CURVES:
            return (
                f"an EC key on {key.curve.name}; only P-256, P-384 and P-521 are "
                "accepted"
            )
        return None
    if isinstance(key, rsa.RSAPublicKey):
        if key.key_size < RSA_MIN_BITS:
            return (
                f"an RSA key of {key.key_size} bits; at least {RSA_MIN_BITS} are needed"
            )
        exponent = key.public_numbers().e
        if exponent < RSA_MIN_EXPONENT:
            return (
                f"an RSA key with exponent {exponent}; at least {RSA_MIN_EXPONENT} "
                "is needed"
            )
        if exponent >= RSA_EXPONENT_LIMIT:
            return (
                f"an RSA key with a {exponent.bit_length()}-bit exponent; it must be "
                "below 2^256"
            )
        return None
    return f"an unsupported key type ({_key_type(key)})"


def _check_key(cert: x509.Certificate, fp: str) -> None:
    problem = key_problem(cert)
    if problem:
        raise OperatorAuthError(f"certificate {fp[:16]} has {problem}", "weak key", fp)


def _key_type(key) -> str:
    if isinstance(key, ec.EllipticCurvePublicKey):
        return f"EC {key.curve.name}"
    if isinstance(key, rsa.RSAPublicKey):
        return f"RSA {key.key_size}"
    return type(key).__name__


def subject(cert: x509.Certificate) -> str:
    names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(names[0].value) if names else cert.subject.rfc4514_string()


class CardAuthenticator:
    def __init__(
        self,
        operators_dir: Path,
        *,
        module: str | None = None,
        token: str | None = None,
        key_id: str = DEFAULT_KEY_ID,
        timeout: float = TIMEOUT,
    ):
        self.operators_dir = Path(operators_dir)
        self.module = module or default_module()
        self.token = token
        self.key_id = key_id
        self.timeout = timeout

    @classmethod
    def from_env(cls, operators_dir: Path, environ) -> "CardAuthenticator":
        return cls(
            operators_dir,
            module=environ.get(MODULE_ENV) or None,
            token=environ.get(TOKEN_ENV) or None,
            key_id=environ.get(OBJECT_ID_ENV) or DEFAULT_KEY_ID,
        )

    def authenticate(self, command: str, store: Path, pin: bytes) -> dict:
        """Facts about the operator who signed, or OperatorAuthError: the
        fingerprint and subject, and user and name for a named operator."""
        pinned = load_pinned(self.operators_dir)
        if not pinned:
            raise OperatorAuthError(
                f"no pinned operator certificates in {self.operators_dir}",
                "no pinned certificates",
            )
        # Before the card is asked for anything, so a broken file costs no PIN try.
        identities = load_identities(self.operators_dir)
        with tempfile.TemporaryDirectory(prefix="ngari-card-") as tmp:
            work = Path(tmp)
            os.chmod(work, 0o700)
            _, fp = self._presented(work)
            cert = pinned.get(fp)
            if cert is None:
                raise OperatorAuthError(
                    f"the card's certificate {fp[:16]} is not pinned in "
                    f"{self.operators_dir}",
                    "not pinned",
                    fp,
                )
            _check_validity(cert, fp)
            _check_key(cert, fp)
            message = challenge(command, store, fp, secrets.token_bytes(32))
            signature = self._sign(work, cert, message, pin, fp)
        self._verify(cert, signature, message, fp)
        return {"fingerprint": fp, "subject": subject(cert), **identities.get(fp, {})}

    def esign(
        self,
        record: str,
        meaning: str,
        pin: bytes,
        roles: dict | None = None,
        role: str | None = None,
    ) -> dict:
        """The card signs record (a SHA-256 hex digest) with meaning. The
        card's certificate must be pinned and named, and with roles set the
        operator must hold role: both are checked before the card is asked
        to sign. Facts for the esignature entry, or OperatorAuthError."""
        pinned = load_pinned(self.operators_dir)
        if not pinned:
            raise OperatorAuthError(
                f"no pinned operator certificates in {self.operators_dir}",
                "no pinned certificates",
            )
        identities = load_identities(self.operators_dir)
        with tempfile.TemporaryDirectory(prefix="ngari-card-") as tmp:
            work = Path(tmp)
            os.chmod(work, 0o700)
            _, fp = self._presented(work)
            cert = pinned.get(fp)
            if cert is None:
                raise OperatorAuthError(
                    f"the card's certificate {fp[:16]} is not pinned in "
                    f"{self.operators_dir}",
                    "not pinned",
                    fp,
                )
            _check_validity(cert, fp)
            _check_key(cert, fp)
            identity = identities.get(fp)
            if identity is None:
                raise OperatorAuthError(
                    f"certificate {fp[:16]} has no named operator, and a signature "
                    "must show the signer's name (keys pin-operator)",
                    "not named",
                    fp,
                )
            user, name = identity["user"], identity["name"]
            if roles is not None and role not in roles.get(user, []):
                raise OperatorAuthError(
                    f"{user} does not hold the {role} role needed to sign for "
                    f"{meaning}",
                    "role",
                    fp,
                )
            signed_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            nonce = secrets.token_hex(16)
            message = esign_message(record, meaning, user, name, fp, signed_at, nonce)
            signature = self._sign(work, cert, message, pin, fp)
        self._verify(cert, signature, message, fp)
        return {
            "user": user,
            "name": name,
            "fingerprint": fp,
            "signed_at": signed_at,
            "nonce": nonce,
            "signature": signature.hex(),
        }

    def sign_named(
        self,
        message_for: Callable[[str, str, str, str, str], bytes],
        pin: bytes,
        roles: dict | None = None,
        role: str | None = None,
        purpose: str = "sign this",
    ) -> dict:
        """The card signs message_for(user, name, fingerprint, signed_at,
        nonce), with the same checks as esign: a pinned, named certificate,
        valid now, with a key the kernel accepts, and with roles set the
        operator must hold role; all before the card is asked to sign. Facts
        about the signer and the signature (hex), or OperatorAuthError."""
        pinned = load_pinned(self.operators_dir)
        if not pinned:
            raise OperatorAuthError(
                f"no pinned operator certificates in {self.operators_dir}",
                "no pinned certificates",
            )
        identities = load_identities(self.operators_dir)
        with tempfile.TemporaryDirectory(prefix="ngari-card-") as tmp:
            work = Path(tmp)
            os.chmod(work, 0o700)
            _, fp = self._presented(work)
            cert = pinned.get(fp)
            if cert is None:
                raise OperatorAuthError(
                    f"the card's certificate {fp[:16]} is not pinned in "
                    f"{self.operators_dir}",
                    "not pinned",
                    fp,
                )
            _check_validity(cert, fp)
            _check_key(cert, fp)
            identity = identities.get(fp)
            if identity is None:
                raise OperatorAuthError(
                    f"certificate {fp[:16]} has no named operator, and only a named "
                    "operator can sign (keys pin-operator)",
                    "not named",
                    fp,
                )
            user, name = identity["user"], identity["name"]
            if roles is not None and role not in roles.get(user, []):
                raise OperatorAuthError(
                    f"{user} does not hold the {role} role needed to {purpose}",
                    "role",
                    fp,
                )
            signed_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            nonce = secrets.token_hex(16)
            message = message_for(user, name, fp, signed_at, nonce)
            signature = self._sign(work, cert, message, pin, fp)
        self._verify(cert, signature, message, fp)
        return {
            "user": user,
            "name": name,
            "fingerprint": fp,
            "signed_at": signed_at,
            "nonce": nonce,
            "signature": signature.hex(),
        }

    def presented(self) -> dict:
        """Whose card is in the reader, read without the PIN: the
        certificate's fingerprint and subject, whether it is pinned here, for
        a named operator their user and name, and problem: why the gate and
        records sign would refuse the card (not pinned, out of date, a key
        they do not accept), or None. It proves nothing about who holds the
        card, only a signature does; an application uses it to refuse a step
        before asking for the PIN."""
        pinned = load_pinned(self.operators_dir)
        identities = load_identities(self.operators_dir)
        with tempfile.TemporaryDirectory(prefix="ngari-card-") as tmp:
            work = Path(tmp)
            os.chmod(work, 0o700)
            cert, fp = self._presented(work)
        facts = {"fingerprint": fp, "subject": subject(cert), "pinned": fp in pinned}
        facts.update(identities.get(fp, {}))
        if "user" in facts:
            facts.setdefault("person", facts["user"])
        problem = None
        if fp not in pinned:
            problem = f"certificate {fp[:16]} is not pinned in {self.operators_dir}"
        else:
            try:
                _check_validity(pinned[fp], fp)
                _check_key(pinned[fp], fp)
            except OperatorAuthError as exc:
                problem = str(exc)
        facts["problem"] = problem
        return facts

    def check(self, store: Path, pin: bytes) -> dict:
        """Prove the card holds the key for the certificate it presents,
        whether or not it is pinned: a fresh challenge for `keys card-check`
        signed with the PIN, verified against the card's own certificate.
        Facts about the card, or OperatorAuthError. Changes nothing."""
        with tempfile.TemporaryDirectory(prefix="ngari-card-") as tmp:
            work = Path(tmp)
            os.chmod(work, 0o700)
            cert, fp = self._presented(work)
            _check_validity(cert, fp)
            _check_key(cert, fp)
            message = challenge(CARD_CHECK, store, fp, secrets.token_bytes(32))
            signature = self._sign(work, cert, message, pin, fp)
        self._verify(cert, signature, message, fp, against="its own")
        return {
            "fingerprint": fp,
            "subject": subject(cert),
            "key": _key_type(cert.public_key()),
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
            "pinned": fp in load_pinned(self.operators_dir),
            "pem": cert.public_bytes(serialization.Encoding.PEM),
        }

    def _presented(self, work: Path) -> tuple[x509.Certificate, str]:
        """The certificate on the card and its SHA-256 fingerprint. No PIN."""
        self._tool(
            work, "--read-object", "--type", "cert", "--id", self.key_id,
            "-o", "card.der",
        )  # fmt: skip
        try:
            cert = x509.load_der_x509_certificate((work / "card.der").read_bytes())
        except (OSError, ValueError):
            raise OperatorAuthError(
                "the card's certificate could not be read", "card"
            ) from None
        return cert, cert.fingerprint(hashes.SHA256()).hex()

    def _sign(self, work, cert, message, pin, fp) -> bytes:
        key = cert.public_key()
        if isinstance(key, ec.EllipticCurvePublicKey):
            # PIV cards and SoftHSM offer raw ECDSA only: hash here.
            (work / "in.bin").write_bytes(hashlib.sha256(message).digest())
            mechanism = ("--mechanism", "ECDSA", "--signature-format", "openssl")
        elif isinstance(key, rsa.RSAPublicKey):
            (work / "in.bin").write_bytes(message)
            mechanism = ("--mechanism", "SHA256-RSA-PKCS")
        else:
            raise OperatorAuthError(
                f"certificate {fp[:16]} has an unsupported key type",
                "unsupported key",
                fp,
            )
        self._tool(
            work, "--login", "--pin", f"env:{_PIN_VAR}", "--sign",
            "--id", self.key_id, *mechanism, "-i", "in.bin", "-o", "sig.bin",
            pin=pin, fingerprint=fp,
        )  # fmt: skip
        return (work / "sig.bin").read_bytes()

    @staticmethod
    def _verify(cert, signature, message, fp, against: str = "the pinned") -> None:
        key = cert.public_key()
        try:
            if isinstance(key, ec.EllipticCurvePublicKey):
                key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            elif isinstance(key, rsa.RSAPublicKey):
                key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
            else:
                raise OperatorAuthError(
                    f"certificate {fp[:16]} has an unsupported key type "
                    f"({_key_type(key)})",
                    "unsupported key",
                    fp,
                )
        except (InvalidSignature, ValueError):
            raise OperatorAuthError(
                f"the card's signature does not verify against {against} "
                f"certificate {fp[:16]}",
                "signature",
                fp,
            ) from None

    def _tool(self, work, *args, pin: bytes | None = None, fingerprint="unknown"):
        tool = shutil.which("pkcs11-tool")
        if tool is None:
            raise OperatorAuthError(
                "pkcs11-tool not found on PATH (Debian and Ubuntu package: opensc)",
                "card",
                fingerprint,
            )
        argv = [tool, "--module", self.module]
        if self.token:
            argv += ["--token-label", self.token]
        env = {k: v for k, v in os.environ.items() if k != _PIN_VAR}
        if pin is not None:
            try:
                text = pin.decode("utf-8", "strict")
            except UnicodeDecodeError:
                raise OperatorAuthError(
                    "the PIN is not UTF-8 text (a PIN file saved as UTF-16 or "
                    "Latin-1?)",
                    "no pin",
                    fingerprint,
                ) from None
            if "\0" in text:
                raise OperatorAuthError(
                    "the PIN holds a NUL byte", "no pin", fingerprint
                )
            env[_PIN_VAR] = text
        try:
            proc = subprocess.run(
                [*argv, *args],
                cwd=work,
                env=env,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise OperatorAuthError(
                f"pkcs11-tool did not finish within {self.timeout:g}s",
                "card",
                fingerprint,
            ) from None
        if proc.returncode != 0:
            text = proc.stderr.decode("utf-8", "replace")
            if pin:
                text = text.replace(pin.decode("utf-8", "replace"), "[pin]")
            lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
            errors = [ln for ln in lines if ln.lower().startswith("error")]
            line = (errors or lines or ["no error output"])[0][:200]
            reason = (
                "pin" if "PIN_INCORRECT" in text or "PIN_LOCKED" in text else "card"
            )
            problem = card_problem(self.module, text)
            if problem:
                line = f"{line}; {problem}"
            raise OperatorAuthError(f"pkcs11-tool failed: {line}", reason, fingerprint)
        return proc.stdout
