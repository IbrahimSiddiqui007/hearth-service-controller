"""Small bounded five-field UTC cron contract (no commands or time-zone data)."""
import re
from datetime import timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


def zone(name):
    if name == 'UTC':
        return timezone.utc
    if not isinstance(name, str) or not re.fullmatch(r'[a-zA-Z0-9_+/-]{1,100}', name) or '..' in name:
        raise ValueError('Use an installed IANA timezone, for example Asia/Dubai')
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        raise ValueError('Timezone could not be resolved; use a known IANA name or UTC')


def local_minute(stamp, name):
    # Nonexistent spring-forward minutes never match. A repeated fall-back
    # minute is eligible only at fold=0, preventing a second wall-clock action.
    local = stamp.astimezone(zone(name))
    return local if local.fold == 0 else None


def parse(expression):
    fields = expression.split()
    if len(fields) != 5 or len(expression) > 100:
        raise ValueError('Use five UTC cron fields: minute hour day month weekday')
    result = []
    for text, low, high in zip(fields, (0, 0, 1, 1, 0), (59, 23, 31, 12, 6)):
        values = set()
        for part in text.split(','):
            if not re.fullmatch(r'(?:\*|\d{1,2}(?:-\d{1,2})?)(?:/\d{1,2})?', part):
                raise ValueError('Cron supports numbers, *, ranges, lists and steps; Sunday is 0')
            base, _, step = part.partition('/')
            step = int(step or 1)
            if not 1 <= step <= high - low + 1:
                raise ValueError('Cron step is outside its field range')
            start, end = (low, high) if base == '*' else (int(base.split('-')[0]), int(base.split('-')[-1]))
            if step and '/' in part and base != '*' and '-' not in base:
                end = high
            if not low <= start <= end <= high:
                raise ValueError('Cron number is outside its field range')
            values.update(range(start, end + 1, step))
        result.append(values)
    # Traditional cron ORs restricted day-of-month and weekday fields.
    return result, any(part.split('/')[0] == '*' for part in fields[2].split(',')), any(part.split('/')[0] == '*' for part in fields[4].split(','))


def matches(parsed, stamp):
    fields, day_any, weekday_any = parsed
    minute, hour, day, month, weekday = fields
    dow = (stamp.weekday() + 1) % 7
    days = (stamp.day in day and dow in weekday) if day_any or weekday_any else (stamp.day in day or dow in weekday)
    return stamp.minute in minute and stamp.hour in hour and stamp.month in month and days


def preview(rules, stamp, timezone_name='UTC'):
    parsed = [parse(row['cron']) for row in rules]
    found = []
    start = stamp.replace(second=0, microsecond=0)
    for offset in range(1, 8 * 24 * 60 + 1):
        candidate = start + timedelta(minutes=offset)
        local = local_minute(candidate, timezone_name)
        if local is None:
            continue
        for index, rule in enumerate(rules):
            if matches(parsed[index], local):
                found.append({'ts': candidate.isoformat(), 'local_ts': local.isoformat(), 'action': rule['action'], 'rule': index})
        if len(found) >= 12:
            break
    return found[:12]
