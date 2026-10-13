"""Return fixed categories only; bounded checks never expose matches or value hashes."""
from shared.configuration import secret_reasons

CATEGORIES = ('Recognized secret assignment or credential URL', 'Private key or recognized credential token',
              'High-entropy value; keep possible credentials out of history', 'Secret-bearing filename; content was not read')


def categories(value):
    reasons, remaining = set(), 2_000_000
    stack = [(None, value)]
    count = 0
    while stack and remaining > 0 and count < 2000:
        key, item = stack.pop()
        count += 1
        if isinstance(item, dict):
            stack.extend([(name, child) for name, child in item.items() if name not in ('secret_categories', 'secret_scan_scope')][:max(0, 2000 - count)])
        elif isinstance(item, (tuple, list)):
            stack.extend((None, child) for child in item[:max(0, 2000 - count)])
        elif isinstance(item, str):
            text = item[:remaining]
            if isinstance(key, str) and len(key) <= 100:
                text = key + '=' + text
            remaining -= len(text)
            reasons.update(secret_reasons(text))
    return [reason for reason in CATEGORIES if reason in reasons]
