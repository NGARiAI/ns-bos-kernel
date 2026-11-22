"""PII redaction: email addresses, phone, SSN and card numbers and street
addresses are replaced by their kind in every audit entry (always) and in the
kernel's log lines (unless NGARI_REDACT_PII=0). Hashes, UUIDs, hex and time
stamps, which the audit chain depends on, are never touched."""

import hashlib
import json
import os
import random
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from core.kernel.data_plane import SovereignDataPlane
from core.kernel.data_plane.redact import RedactingFormatter, redact, redact_values

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.parametrize(
    ("text", "expected"),
    [("mail john.doe+x@example.co.uk now", "mail [email] now"),
     ("ssn 123-45-6789.", "ssn [ssn]."),
     ("card 4111 1111 1111 1111 ok", "card [card] ok"),
     ("card 4111-1111-1111-1111", "card [card]"),
     ("card 5500005555555559", "card [card]"),
     ("call (415) 555-0132", "call [phone]"),
     ("call 415.555.0132", "call [phone]"),
     ("call +1 415 555 0132", "call [phone]"),
     ("call +14155550132", "call [phone]"),
     ("at 1600 Pennsylvania Ave", "at [address]"),
     ("at 10 Downing St.", "at [address]"),
     ("at 221 Baker Street, London", "at [address], London"),
     ("4111 1111 1111 1111 10 Downing St", "[card] [address]"),
     ("4111-1111-1111-1111-123", "[card]-123")],
)  # fmt: skip
def test_each_kind_is_replaced(text, expected):
    assert redact(text) == expected


@pytest.mark.parametrize(
    "text",
    ["order 1234567890123456 fails the card check", "ip 203.0.113.7 port 11434 v0.1.0",
     "ssn-like 000-12-3456 and 666-12-3456 are not issued", "2026-10-31T03:11:55.597711+00:00",
     "orders_20261031_031155_597711_fc8d4966.json", "20261031T031155Z",
     "21171984-5266-4186-9ef7-f37687679b47", "agent.CEO", "sha256:7"],
)  # fmt: skip
def test_what_is_not_pii_is_left(text):
    assert redact(text) == text


def test_hashes_uuids_hex_and_time_stamps_are_never_touched():
    rng = random.Random(72)
    for _ in range(20_000):
        values = [
            hashlib.sha256(rng.randbytes(8)).hexdigest(),
            str(uuid.UUID(int=rng.getrandbits(128))),
            str(uuid.UUID(int=rng.randrange(10**30))),  # long digit runs
            rng.randbytes(16).hex(),
            datetime.fromtimestamp(rng.randrange(4 * 10**9), timezone.utc).isoformat(),
        ]
        assert [redact(v) for v in values] == values


@pytest.mark.parametrize(
    ("text", "expected"),
    [("patient_123-45-6789", "patient_[ssn]"),
     ("card_5500005555555559", "card_[card]"),
     ("phone_415-555-0132", "phone_[phone]"),
     ("jane.doe@example.com_notes", "[email]_notes"),
     ("notes_jane.doe@example.com", "[email]")],  # the local part takes _
)  # fmt: skip
def test_pii_joined_by_an_underscore_is_redacted(text, expected):
    assert redact(text) == expected


def test_message_file_names_keep_their_time_and_lose_their_pii():
    name = "patient 123-45-6789_20261031_140509_004632_0a0b0c0d.json"
    assert redact(name) == "patient [ssn]_20261031_140509_004632_0a0b0c0d.json"
    plain = "orders_20261031_140509_004632_0a0b0c0d.json"
    assert redact(plain) == plain


def test_an_event_topic_does_not_reach_the_log_through_its_file_name(
    tmp_path, monkeypatch
):
    import json

    from core.kernel import NSBOSKernel

    monkeypatch.setenv("NGARI_DATA_DIR", str(tmp_path))
    kernel = NSBOSKernel()
    topics = ("patient 123-45-6789", "call 415-555-0132",
              "notify jane.doe@example.com", "card 4111 1111 1111 1111")  # fmt: skip
    for topic in topics:
        kernel.publish_event(topic, {"x": 1})
    raw = kernel.data_plane.audit_log.read_text()
    published = [json.loads(x) for x in raw.splitlines() if '"event_published"' in x]
    assert len(published) == 4
    assert all("[" in e["resource"] and "[" in e["details"]["file"] for e in published)
    for pii in ("123-45-6789", "555-0132", "jane.doe@example.com", "4111 1111"):
        assert pii not in raw, pii
    assert kernel.data_plane.verify_audit_integrity()


@pytest.mark.parametrize(
    ("text", "expected"),
    [("visit 3 4111 1111 1111 1111", "visit 3 [card]"),
     ("item 12 5500005555555559", "item 12 [card]"),
     ("room 7 5555-5555-5555-4444", "room 7 [card]"),
     ("3782 822463 10005 4111 1111 1111 1111", "[card] [card]"),  # Amex, then Visa
     ("4222222222222 4111 1111 1111 1111", "[card] [card]"),
     ("4111 1111 1111 1111 5555 5555 5555 4444", "[card] [card]"),
     ("4111-1111-1111-1111-123", "[card]-123")],
)  # fmt: skip
def test_every_card_in_a_run_of_numbers_is_redacted(text, expected):
    assert redact(text) == expected


def test_a_uuid_written_in_digits_is_never_split():
    rng = random.Random(94)
    for _ in range(5_000):
        digits = "".join(rng.choice("0123456789") for _ in range(32))
        value = (
            f"{digits[:8]}-{digits[8:12]}-{digits[12:16]}-{digits[16:20]}-{digits[20:]}"
        )
        assert redact(value) == value
        assert redact(f"id {value} ok") == f"id {value} ok"


def test_card_redaction_takes_linear_time():
    import time

    def took(size):
        text = ("1 " * size)[:size]
        began = time.perf_counter()
        redact(text)
        return time.perf_counter() - began

    took(1_000)  # warm up
    small, large = took(20_000), took(200_000)
    assert large < 30 * max(small, 1e-4), (small, large)  # 10x input, not 100x time


@pytest.mark.parametrize(
    "number",
    ["1-800-555-0199", "1-415-555-0132", "1.415.555.0132", "+44 20 7946 0958",
     "+44 7700 900123", "+33 1 23 45 67 89", "+49 30 12345678", "+91 98765 43210",
     "+61 2 9876 5432", "+81 3-1234-5678"],
)  # fmt: skip
def test_common_phone_forms_are_redacted(number):
    assert redact(f"call {number} today") == "call [phone] today"


@pytest.mark.parametrize(
    "text",
    ["v+1.2.3", "offset +05:30", "build +1.2.3", "+12 3", "+44 20"],
)  # fmt: skip
def test_short_or_long_plus_numbers_are_not_phones(text):
    assert redact(text) == text


@pytest.mark.parametrize(
    "text",
    ["connect 203.0.113.200 8080", "host 198.51.100.200 5432", "at 203.0.113.250 4433 now"],
)  # fmt: skip
def test_an_ip_address_and_a_port_are_not_a_phone(text):
    assert redact(text) == text


@pytest.mark.parametrize(
    "address",
    ["123 N Main St", "350 5th Avenue", "100 W 34th St", "12 E. 42nd Street",
     "1 S Ocean Blvd", "221 Baker St"],
)  # fmt: skip
def test_streets_with_a_direction_or_a_number_are_redacted(address):
    assert redact(f"at {address} today") == "at [address] today"


@pytest.mark.parametrize(
    ("text", "expected"),
    [("ssn 123 45 6789", "ssn [ssn]"), ("ssn 123-45-6789 ok", "ssn [ssn] ok"),
     ("ssn 123-45 6789", "ssn 123-45 6789"),  # mixed: not an SSN's form
     ("ssn 000 12 3456", "ssn 000 12 3456"), ("ssn 666 12 3456", "ssn 666 12 3456"),
     ("ssn 123 00 4567", "ssn 123 00 4567"), ("ssn 123 45 0000", "ssn 123 45 0000")],
)  # fmt: skip
def test_an_ssn_with_spaces_is_redacted(text, expected):
    assert redact(text) == expected


def test_twelve_digits_are_too_few_for_a_card_even_when_luhn_valid():
    # 835337406812 passes Luhn; with the 1 the run has 13 digits, which do not.
    for text in ("order 835337406812 shipped", "order 835337406812 1 shipped"):
        assert redact(text) == text


def test_more_than_fifteen_digits_after_a_plus_is_not_a_phone():
    # 18 digits: past E.164, and no window of its groups passes the card check.
    assert (
        redact("call +44 3662 5851 7812 8657 now") == "call +44 3662 5851 7812 8657 now"
    )


def test_the_international_pattern_takes_linear_time():
    import time

    def took(size):
        text = (" +1234567890123456789012345678901x" * size)[: size * 34]
        began = time.perf_counter()
        redact(text)
        return time.perf_counter() - began

    took(100)
    small, large = took(2_000), took(20_000)
    assert large < 30 * max(small, 1e-4), (small, large)


def test_values_are_redacted_and_keys_kept():
    details = {
        "john@example.com": "x",
        "contact": ["a@b.co", 7, {"ssn": "123-45-6789"}],
        "n": 3,
    }
    assert redact_values(details) == {
        "john@example.com": "x", "contact": ["[email]", 7, {"ssn": "[ssn]"}], "n": 3
    }  # fmt: skip


# -- the audit log ---------------------------------------------------------------------


def test_the_audit_log_never_holds_the_pii(tmp_path, monkeypatch):
    from core.kernel import NSBOSKernel

    monkeypatch.setenv("NGARI_DATA_DIR", str(tmp_path))
    kernel = NSBOSKernel()
    agent_id = kernel.register_agent("john.doe@example.com", "sales")
    kernel.create_task(agent_id, "call (415) 555-0132", {})
    kernel.data_plane.store_encrypted("patient 123-45-6789", {"v": 1})
    raw = kernel.data_plane.audit_log.read_text()
    for pii in ("john.doe@example.com", "555-0132", "123-45-6789"):
        assert pii not in raw
    entries = [json.loads(x) for x in raw.splitlines()]
    registered = next(e for e in entries if e["action"] == "agent_registered")
    assert (
        registered["details"]["name"] == "[email]"
        and registered["resource"] == agent_id
    )
    # agent.john.doe@example.com is itself a valid address: it goes whole.
    twin = next(e for e in entries if e["action"] == "twin_updated")
    assert twin["resource"] == "[email]"
    assert (
        next(e for e in entries if e["action"] == "task_created")["details"]["action"]
        == "call [phone]"
    )
    assert any(e["resource"] == "patient [ssn]" for e in entries)
    assert kernel.data_plane.verify_audit_integrity()
    # The data itself is untouched: only what the log says about it is redacted.
    assert kernel.data_plane.retrieve_decrypted("patient 123-45-6789") == {"v": 1}
    assert (
        kernel.agent_runtime.registry.get_agent(agent_id).config.name
        == "john.doe@example.com"
    )


def test_redaction_does_not_break_a_resumed_chain_check(tmp_path):
    plane = SovereignDataPlane(str(tmp_path / "sovereign"))
    for i in range(5):
        plane.store_encrypted(f"user{i}@example.com", {"i": i})
        assert plane.verify_audit_integrity()


# -- the kernel's log lines ------------------------------------------------------------


def test_the_formatter_redacts_messages_and_tracebacks():
    import logging

    formatter = RedactingFormatter("%(message)s")
    try:
        raise ValueError("bad card 4111 1111 1111 1111")
    except ValueError:
        record = logging.LogRecord(
            "t", logging.ERROR, __file__, 1, "for %s", ("a@b.co",), sys.exc_info()
        )
    out = formatter.format(record)
    assert "a@b.co" not in out and "4111 1111" not in out
    assert "for [email]" in out and "bad card [card]" in out


@pytest.mark.parametrize(("setting", "redacted"), [(None, True), ("0", False)])
def test_the_kernel_command_redacts_its_log_lines(tmp_path, setting, redacted):
    # main() logs the refusal of an unknown key provider through its handlers;
    # the provider name carries an email address.
    env = {
        **os.environ,
        "NGARI_DATA_DIR": str(tmp_path),
        "NGARI_KEY_PROVIDER": "pigeon-ops@example.com",
    }
    env.pop("NGARI_REDACT_PII", None)
    if setting is not None:
        env["NGARI_REDACT_PII"] = setting
    run = subprocess.run(
        [sys.executable, "-m", "core.kernel"], cwd=REPO_ROOT, env=env,
        capture_output=True, text=True, timeout=60, check=False,
    )  # fmt: skip
    assert run.returncode == 2
    logged = (tmp_path / "logs" / "kernel.log").read_text() + run.stderr
    assert "Cannot start:" in logged
    assert ("ops@example.com" in logged) is not redacted
    assert ("[email]" in logged) is redacted
