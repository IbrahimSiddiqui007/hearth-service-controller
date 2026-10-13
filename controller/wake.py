"""Explicitly configured Wake-on-LAN; no host state inferred from packet dispatch."""
import asyncio
import hashlib
import ipaddress
import json
import os
import re
import secrets
import socket
from datetime import datetime, timezone

from fastapi import HTTPException
from pydantic import Field
from shared.models import StrictModel
from controller.store import now


class Wake(StrictModel):
    confirmed: bool = False
    fingerprint: str = Field(pattern=r'^[a-f0-9]{64}$')


def profile(hid, demo):
    if demo:
        return {'mac':'02:00:00:00:00:01','address':'192.168.1.255','port':9}
    raw = os.environ.get('PSC_WAKE_PROFILES', '{}')
    if len(raw) > 20000:
        raise HTTPException(409, 'Wake profile configuration exceeds supported size')
    try:
        profiles = json.loads(raw)
        if not isinstance(profiles, dict) or len(profiles) > 50:
            raise ValueError()
        value = profiles.get(hid)
        if not isinstance(value, dict) or set(value) != {'mac', 'address', 'port'}:
            raise ValueError()
        mac = value['mac'].replace('-', ':').lower()
        if not re.fullmatch(r'(?:[a-f0-9]{2}:){5}[a-f0-9]{2}', mac):
            raise ValueError()
        encoded = bytes.fromhex(mac.replace(':', ''))
        if encoded == b'\0' * 6 or encoded[0] & 1:
            raise ValueError()
        address = ipaddress.IPv4Address(value['address'])
        private = any(address in ipaddress.IPv4Network(network) for network in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'))
        if not private and str(address) != '255.255.255.255' or type(value['port']) is not int or value['port'] not in (7,9):
            raise ValueError()
        return {'mac':mac,'address':str(address),'port':value['port']}
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(409, 'Configure a fixed wake profile with a unicast MAC, private IPv4/broadcast address and UDP port 7 or 9')


def send_magic(selected):
    packet = b'\xff' * 6 + bytes.fromhex(selected['mac'].replace(':', '')) * 16
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
        stream.settimeout(2)
        stream.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        if stream.sendto(packet, (selected['address'], selected['port'])) != len(packet):
            raise OSError('Incomplete wake packet dispatch')


def register(app, store, demo, require, lock, busy):
    with store.connection() as db:
        db.execute('CREATE TABLE IF NOT EXISTS wake_requests(host_id TEXT PRIMARY KEY,ts TEXT NOT NULL,status TEXT NOT NULL)')

    def plan(hid):
        host = require('hosts', hid)
        selected = profile(hid, demo)
        binding = [selected, {key:host.get(key) for key in ('id','physical_host_id','agent_url','name')}]
        fingerprint = hashlib.sha256(json.dumps(binding, sort_keys=True).encode()).hexdigest()
        return {'host_id':hid,'host_name':host['name'],**selected,'fingerprint':fingerprint,'demo':demo,'notice':'A sent packet does not prove wake or connectivity. Firmware/NIC and network support require manual verification.'}

    @app.get('/api/v1/hosts/{hid}/wake-plan')
    def wake_plan(hid: str):
        return plan(hid)

    @app.post('/api/v1/hosts/{hid}/wake')
    async def wake(hid: str, body: Wake):
        if not body.confirmed:
            raise HTTPException(409, 'Confirm the configured host, MAC and packet destination')
        async with lock:
            selected = plan(hid)
            if selected['fingerprint'] != body.fingerprint or busy(hid):
                raise HTTPException(409, 'Wake profile/host changed or a host operation is running; review a fresh plan')
            with store.connection() as db:
                last = db.execute('SELECT ts FROM wake_requests WHERE host_id=?', (hid,)).fetchone()
                if last and (datetime.now(timezone.utc)-datetime.fromisoformat(last['ts'])).total_seconds() < 30:
                    raise HTTPException(429, 'Wait 30 seconds before sending another wake packet')
                identifier = secrets.token_hex(16)
                db.execute('INSERT OR REPLACE INTO wake_requests VALUES(?,?,?)', (hid,now(),'pending'))
                db.execute('INSERT INTO operations VALUES(?,?,?,?,?,?)', (identifier,'container:'+hid+':wake','host.wake','running',now(),'Confirmed wake packet'))
        status, detail = 'unknown', 'Packet dispatch failed or timed out; wake is unverified'
        try:
            if not demo:
                await asyncio.to_thread(send_magic, selected)
            status, detail = 'sent', 'Synthetic wake; no packet sent' if demo else 'Wake packet dispatched; waiting for observed host connectivity'
            return {'status':status,'detail':detail,'demo':demo,'host_state_verified':False}
        except OSError as exc:
            raise HTTPException(503, detail) from exc
        finally:
            with store.connection() as db:
                db.execute('UPDATE wake_requests SET status=? WHERE host_id=?', (status,hid))
                db.execute('UPDATE operations SET status=?,detail=? WHERE id=?', (status,detail,identifier))
                store.audit('host.wake',status,detail,host_id=hid,db=db)
