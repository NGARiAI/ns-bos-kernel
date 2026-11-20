"""The data plane demo: `python -m core.kernel.data_plane`.

It stores, reads back and reports on one record. A data plane built with no
directory uses $NGARI_DATA_DIR itself (default ~/.ngari/kernel), not the
kernel's sovereign/ below it, so it keeps its own master key there; run it
on a scratch directory, never on a deployment's.
"""

import json
import logging
from datetime import datetime, timezone

from . import SovereignDataPlane

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    dp = SovereignDataPlane()

    # Store one record and read it back.
    test_data = {
        "user": "test",
        "secret": "sovereign_data",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    dp.store_encrypted("test_key", test_data)

    retrieved = dp.retrieve_decrypted("test_key")
    print(f"Retrieved: {retrieved}")

    # Each call above wrote an audit entry.
    audit = dp.get_audit_log()
    print(f"Audit entries: {len(audit)}")

    # Every field of the report is measured at call time.
    report = dp.export_compliance_report()
    print(f"Compliance report: {json.dumps(report, indent=2)}")
