import json
import re
from shared.models import redact


class LineMask:
    def __init__(self):
        self.private = False

    def apply(self, text):
        if self.private or re.search(r'-----BEGIN .*PRIVATE KEY-----', text):
            self.private = '-----END ' not in text
            return '[REDACTED private key material]\n'
        return redact(text)


def frame(kind, content):
    return json.dumps({'kind': kind, 'content': content}, ensure_ascii=True) + '\n'
