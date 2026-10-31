import json
from pathlib import Path

import pytest

from gateway.pii import luhn_ok, redact, verhoeff_ok

CASES = [json.loads(l) for l in (Path(__file__).parents[1] / "data/pii_cases.jsonl").read_text().splitlines() if l]


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_labelled_pii_cases(case):
    _, found = redact(case["text"])
    assert dict(found) == case["expected"]


def test_placeholders_replace_values():
    out, found = redact("mail priya@example.com, card 4111 1111 1111 1111")
    assert out == "mail <REDACTED_EMAIL>, card <REDACTED_CREDIT_CARD>"
    assert "priya" not in out and "4111" not in out


def test_checksums():
    assert luhn_ok("4111111111111111") and not luhn_ok("4111111111111112")
    assert verhoeff_ok("234567890124") and not verhoeff_ok("234567890125")


def test_benign_text_untouched():
    text = "Q3 revenue grew 12% to 4500 units in 2024; see section 3.2.1"
    assert redact(text) == (text, {})
