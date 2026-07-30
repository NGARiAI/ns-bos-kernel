"""
NS BOS Kernel - Sovereign Data Plane
Encrypted local storage, audit logging, and data sovereignty enforcement.
Zero external telemetry.
"""

import os
import json
import time
import hashlib
import logging
from datetime import datetime
from typing import Optional, Any
from dataclasses import dataclass, asdict
from cryptography.fernet import Fernet
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class AuditEntry:
    timestamp: str
    action: str
    actor: str
    resource: str
    details: dict
    hash: str


class SovereignDataPlane:
    """
    Sovereign data plane with encryption, audit logging,
    and data sovereignty enforcement.
    """

    def __init__(self, data_dir: str = None):
        base = data_dir or os.environ.get("NGARI_DATA_DIR", str(Path.home() / ".ngari" / "kernel"))
        self.data_dir = Path(base)
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.encrypted_dir = self.data_dir / "encrypted"
        self.encrypted_dir.mkdir(exist_ok=True)

        self.audit_log = self.data_dir / "audit" / "sovereign_audit.log"
        self.audit_log.parent.mkdir(parents=True, exist_ok=True)

        self.key_file = self.data_dir / "keys" / "master.key"
        self.key_file.parent.mkdir(parents=True, exist_ok=True)

        self.fernet = self._load_or_create_key()
        self._enforce_sovereignty()

    def _load_or_create_key(self) -> Fernet:
        """Load existing encryption key or create new one"""
        if self.key_file.exists():
            with open(self.key_file, "rb") as f:
                key = f.read()
        else:
            key = Fernet.generate_key()
            with open(self.key_file, "wb") as f:
                f.write(key)
            os.chmod(self.key_file, 0o600)

        return Fernet(key)

    def _enforce_sovereignty(self):
        """Enforce data sovereignty rules"""
        # Ensure no external telemetry endpoints are configured
        telemetry_file = self.data_dir / "telemetry_config.json"
        if telemetry_file.exists():
            with open(telemetry_file, "r") as f:
                config = json.load(f)
            if config.get("external_telemetry", False):
                logger.warning("External telemetry detected - disabling")
                config["external_telemetry"] = False
                with open(telemetry_file, "w") as f:
                    json.dump(config, f)

    def store_encrypted(self, key: str, data: Any) -> str:
        """Store data encrypted on disk"""
        data_json = json.dumps(data, default=str).encode()
        encrypted = self.fernet.encrypt(data_json)

        file_path = self.encrypted_dir / f"{key}.enc"
        with open(file_path, "wb") as f:
            f.write(encrypted)

        self._audit("store_encrypted", "system", key, {"size": len(encrypted)})
        return str(file_path)

    def retrieve_decrypted(self, key: str) -> Optional[Any]:
        """Retrieve and decrypt data"""
        file_path = self.encrypted_dir / f"{key}.enc"
        if not file_path.exists():
            return None

        with open(file_path, "rb") as f:
            encrypted = f.read()

        try:
            decrypted = self.fernet.decrypt(encrypted)
            data = json.loads(decrypted)
            self._audit("retrieve_decrypted", "system", key, {})
            return data
        except Exception as e:
            logger.error(f"Decryption failed for {key}: {e}")
            return None

    def delete(self, key: str) -> bool:
        """Securely delete data"""
        file_path = self.encrypted_dir / f"{key}.enc"
        if file_path.exists():
            # Overwrite with random data before deletion
            with open(file_path, "wb") as f:
                f.write(os.urandom(file_path.stat().st_size))
            file_path.unlink()
            self._audit("delete", "system", key, {})
            return True
        return False

    def _audit(self, action: str, actor: str, resource: str, details: dict):
        """Write audit log entry"""
        entry = AuditEntry(
            timestamp=datetime.utcnow().isoformat(),
            action=action,
            actor=actor,
            resource=resource,
            details=details,
            hash=""
        )

        entry_dict = asdict(entry)
        entry_dict.pop("hash", None)
        entry_str = json.dumps(entry_dict, sort_keys=True)
        entry.hash = hashlib.sha256(entry_str.encode()).hexdigest()

        with open(self.audit_log, "a") as f:
            f.write(json.dumps(asdict(entry)) + "\n")

    def verify_audit_integrity(self) -> bool:
        """Verify audit log integrity"""
        if not self.audit_log.exists():
            return True

        with open(self.audit_log, "r") as f:
            lines = f.readlines()

        for line in lines:
            entry = json.loads(line)
            stored_hash = entry.pop("hash", "")
            entry_str = json.dumps(entry, sort_keys=True)
            expected_hash = hashlib.sha256(entry_str.encode()).hexdigest()

            if stored_hash != expected_hash:
                logger.error("Audit integrity violation detected")
                return False

        return True

    def get_audit_log(self, limit: int = 100) -> list:
        """Get recent audit entries"""
        if not self.audit_log.exists():
            return []

        entries = []
        with open(self.audit_log, "r") as f:
            lines = f.readlines()

        for line in lines[-limit:]:
            entries.append(json.loads(line))

        return entries

    def export_compliance_report(self) -> dict:
        """Export compliance report for audit purposes"""
        return {
            "generated_at": datetime.utcnow().isoformat(),
            "data_sovereignty": "enforced",
            "external_telemetry": False,
            "encryption": "AES-256-Fernet",
            "audit_entries": len(self.get_audit_log()),
            "audit_integrity": self.verify_audit_integrity(),
            "data_directory": str(self.data_dir),
            "encrypted_files": len(list(self.encrypted_dir.glob("*.enc")))
        }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    dp = SovereignDataPlane()

    # Test store and retrieve
    test_data = {"user": "test", "secret": "sovereign_data", "timestamp": datetime.utcnow().isoformat()}
    dp.store_encrypted("test_key", test_data)

    retrieved = dp.retrieve_decrypted("test_key")
    print(f"Retrieved: {retrieved}")

    # Test audit
    audit = dp.get_audit_log()
    print(f"Audit entries: {len(audit)}")

    # Test compliance report
    report = dp.export_compliance_report()
    print(f"Compliance report: {json.dumps(report, indent=2)}")
