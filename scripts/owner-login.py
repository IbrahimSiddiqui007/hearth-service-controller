"""Run interactively to prepare credentials; never writes an environment file."""
import base64
import getpass
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from controller.login import password_hash


def main():
    password = getpass.getpass('New controller owner password: ')
    if len(password) < 12:
        raise SystemExit('Use at least 12 characters')
    if password != getpass.getpass('Repeat password: '):
        raise SystemExit('Passwords did not match')
    secret = base64.b32encode(secrets.token_bytes(20)).decode().rstrip('=')
    print('Store these privately in the controller environment; do not paste them into notes.')
    print('PSC_PASSWORD_HASH=' + password_hash(password))
    print('PSC_TOTP_SECRET=' + secret)
    print('Add the TOTP secret to your authenticator (6 digits, SHA-1, 30-second period).')


if __name__ == '__main__':
    main()
