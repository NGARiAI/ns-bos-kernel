"""Best-effort PII redaction by pattern: email addresses, phone numbers, US
social security numbers, payment card numbers and street addresses become
[email], [phone], [ssn], [card] and [address].

Patterns find the usual forms and miss others (a phone number written as
words, an address with no number or street word, a name). Every pattern is
bounded by letters and digits, so digits inside a hash, a UUID or a time
stamp, which the audit chain depends on, are never touched. An underscore is
a boundary, not part of a word: a message file name joins its topic to the
time with one, and snake_case names join words with them."""

import logging
import re

_EMAIL = re.compile(
    r"(?<![A-Za-z0-9.%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*"
    r"\.[A-Za-z]{2,}(?![A-Za-z0-9])",
    re.ASCII,
)
# None of the digit patterns may touch a dash, a letter or a digit at either
# end, so a run inside a UUID (21171984-5266-4186-9ef7-...) or a hash is not
# taken for a number of its own.
# US SSN: area 001-899 but not 666, group 01-99, serial 0001-9999, with
# dashes or with spaces (the same both times).
_SSN = re.compile(
    r"(?<![A-Za-z0-9-])(?!000|666|9\d\d)\d{3}([ -])(?!00)\d{2}\1(?!0000)\d{4}"
    r"(?![A-Za-z0-9-])",
    re.ASCII,
)
# A run of digit groups with single spaces or dashes between them. The card
# numbers in it are found by _cards: 13 to 19 digits of whole groups that
# pass the Luhn check, so most order numbers and counters stay.
_RUN = re.compile(r"(?<![A-Za-z0-9-])\d+(?:[ -]\d+)*(?![A-Za-z0-9-])", re.ASCII)
_SEPARATOR = re.compile(r"([ -])")
_DOUBLED = (0, 2, 4, 6, 8, 1, 3, 5, 7, 9)  # Luhn: a digit doubled, digits summed
# North American: 415-555-0132, (415) 555-0132, +1 415 555 0132, 1-800-555-0199.
# Not from just after a digit and a dot, which would take the end of an IP
# address and a port (203.0.113.200 8080) for one.
_PHONE = re.compile(
    r"(?<![A-Za-z0-9+-])(?<!\d\.)(?:\+\d{1,3}[ .-]?|1[ .-])?(?:\(\d{3}\)[ .-]?|\d{3}[ .-])"
    r"\d{3}[ .-]\d{4}(?![A-Za-z0-9-])"
    r"|(?<![A-Za-z0-9+-])\+\d{8,15}(?![A-Za-z0-9-])",
    re.ASCII,
)
# International, as usually grouped: +44 20 7946 0958, +33 1 23 45 67 89. A
# separator between every group keeps the match from trying every split of
# a digit run; _international keeps it only at 8 to 15 digits (E.164).
_INTERNATIONAL = re.compile(
    r"(?<![A-Za-z0-9+-])\+\d{1,3}(?:[ .-]\d{1,8}){1,6}(?![A-Za-z0-9-])", re.ASCII
)
# 123 Main St, 123 N Main St, 350 5th Avenue, 100 W 34th St.
_ADDRESS = re.compile(
    r"\b\d{1,6}\s+(?:[NSEW]\.?\s+)?(?:(?:[A-Z][a-z]+|\d+(?:st|nd|rd|th))\.?\s+){1,4}"
    r"(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way"
    r"|Place|Pl|Terrace|Parkway|Pkwy|Circle|Cir|Highway|Hwy)\b\.?",
    re.ASCII,
)


def _cards(match: re.Match) -> str:
    """The run with every card number in it as [card]. Of the windows of
    whole groups holding 13 to 19 digits that pass the Luhn check, the
    non-overlapping set that covers the most digits is redacted, so a card
    after a short number ("visit 3 4111 ...") or after another card is found.
    A dash-joined chunk of more than 19 digits (a UUID written in digits)
    cannot be a card and is never split. Linear in the run's length."""
    run = match.group(0)
    parts = _SEPARATOR.split(run)
    groups, seps = parts[0::2], parts[1::2]
    n = len(groups)
    sizes = [len(g) for g in groups]
    if sum(sizes) < 13:
        return run
    blocked = [False] * n
    k = 0
    while k < n:
        m, digits = k, sizes[k]
        while m < n - 1 and seps[m] == "-":
            m += 1
            digits += sizes[m]
        if digits > 19:
            blocked[k : m + 1] = [True] * (m + 1 - k)
        k = m + 1
    # Luhn sums of any span in O(1): even[k] sums the first k digits weighting
    # even positions plain and odd ones doubled, odd[k] the other way round.
    even, odd = [0], [0]
    for position, ch in enumerate("".join(groups)):
        plain, doubled = ord(ch) - 48, _DOUBLED[ord(ch) - 48]
        if position % 2:
            plain, doubled = doubled, plain
        even.append(even[-1] + plain)
        odd.append(odd[-1] + doubled)
    start = [0]
    for size in sizes:
        start.append(start[-1] + size)
    best = [0] * (n + 1)  # most digits coverable from group i on
    take = [0] * (n + 1)  # the end of the window to take at i, or 0
    for i in range(n - 1, -1, -1):
        best[i] = best[i + 1]
        j, digits = i, 0
        while j < n and not blocked[j]:
            digits += sizes[j]
            j += 1
            if digits > 19:
                break
            if digits >= 13:
                lo, hi = start[i], start[j]
                sums = even if (hi - 1) % 2 == 0 else odd
                if (sums[hi] - sums[lo]) % 10 == 0 and digits + best[j] > best[i]:
                    best[i], take[i] = digits + best[j], j
    if not best[0]:
        return run
    out, i = [], 0
    while i < n:
        if take[i]:
            out.append("[card]")
            i = take[i]
        else:
            out.append(groups[i])
            i += 1
        if i < n:
            out.append(seps[i - 1])
    return "".join(out)


def _international(match: re.Match) -> str:
    digits = sum(c.isdigit() for c in match.group(0))
    return "[phone]" if 8 <= digits <= 15 else match.group(0)


def redact(text: str) -> str:
    """text with the PII the patterns find replaced by its kind."""
    if not isinstance(text, str) or not text:
        return text
    text = _EMAIL.sub("[email]", text)
    text = _SSN.sub("[ssn]", text)
    text = _RUN.sub(_cards, text)
    text = _PHONE.sub("[phone]", text)
    text = _INTERNATIONAL.sub(_international, text)
    return _ADDRESS.sub("[address]", text)


def redact_values(value):
    """The same structure with every string value redacted; dictionary keys,
    which are field names, are kept."""
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {k: redact_values(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_values(v) for v in value]
    return value


class RedactingFormatter(logging.Formatter):
    """A logging.Formatter whose output, message and traceback alike, is
    redacted. Install it on a handler with handler.setFormatter()."""

    def format(self, record: logging.LogRecord) -> str:
        return redact(super().format(record))
