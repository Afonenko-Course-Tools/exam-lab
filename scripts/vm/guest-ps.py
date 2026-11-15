#!/usr/bin/env python3
"""Выполнить PowerShell в своей VM через NTLM WinRM с шифрованием сообщений."""
import argparse
import json
from pathlib import Path
import sys
from pypsrp.client import Client

root = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('script', type=Path)
args = parser.parse_args()
creds = json.loads((root / '.local/vm/credentials.json').read_text())
client = Client('127.0.0.1', port=15985, ssl=False, username=creds['username'], password=creds['password'], auth='ntlm', encryption='always')
output, streams, failed = client.execute_ps(args.script.read_text(encoding='utf-8-sig'))
sys.stdout.write(output)
for error in streams.error:
    print(error, file=sys.stderr)
raise SystemExit(1 if failed else 0)
