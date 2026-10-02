#!/usr/bin/env python3
"""Read-only Cudy AP MQTT reachability probe.

Connects to the AP's plaintext broker with the fleet-wide static JWT, subscribes
to $SYS/broker/clients/connected, prints the value, disconnects. Publishes
nothing and changes nothing on the device.

A count of 1 means only this probe is attached, so no cmagent is consuming
commands. A count of 2 or more means an agent is attached and the command topic
has a live consumer.
"""
import base64, hashlib, hmac, json, socket, sys, time

SECRET = 'CLOUDmqttabc&123'
USER = 'admincudydevice'
TOPIC = '$SYS/broker/clients/connected'


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()


def jwt(user):
    h = b64u(b'{"typ":"JWT","alg":"HS256"}')
    p = b64u(json.dumps({'username': user, 'exp': int(time.time()) + 3600},
                        separators=(',', ':')).encode())
    sig = b64u(hmac.new(SECRET.encode(), f'{h}.{p}'.encode(), hashlib.sha256).digest())
    return f'{h}.{p}.{sig}'


def enc_str(v):
    if isinstance(v, str):
        v = v.encode()
    return len(v).to_bytes(2, 'big') + v


def rem_len(n):
    out = b''
    while True:
        d = n & 127
        n >>= 7
        out += bytes([d | 128]) if n else bytes([d])
        if not n:
            return out


def packet(kind, body):
    return bytes([kind]) + rem_len(len(body)) + body


def read_packet(sock):
    hdr = sock.recv(1)
    if not hdr:
        raise EOFError('broker closed connection')
    mult, n = 1, 0
    while True:
        b = sock.recv(1)[0]
        n += (b & 127) * mult
        if not b & 128:
            break
        mult *= 128
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError('short read')
        buf += chunk
    return hdr[0], buf


def probe(host, port=1883, timeout=5.0):
    cid = f'probe{int(time.time()) & 0xffff:04x}'
    s = socket.create_connection((host, port), timeout)
    s.settimeout(timeout)
    try:
        body = enc_str('MQTT') + bytes([4, 0xC2]) + (30).to_bytes(2, 'big') \
            + enc_str(cid) + enc_str(USER) + enc_str(jwt(USER))
        s.sendall(packet(0x10, body))
        kind, buf = read_packet(s)
        if kind >> 4 != 2:
            return f'unexpected reply to CONNECT: 0x{kind:02x}'
        if buf[1] != 0:
            return f'CONNACK refused, return code {buf[1]} (auth rejected)'

        s.sendall(packet(0x82, (1).to_bytes(2, 'big') + enc_str(TOPIC) + b'\x00'))
        deadline = time.time() + timeout
        while time.time() < deadline:
            kind, buf = read_packet(s)
            if kind >> 4 == 9:                     # SUBACK
                if buf[2] == 0x80:
                    return 'SUBACK: subscription denied by ACL'
                continue
            if kind >> 4 == 3:                     # PUBLISH
                tlen = int.from_bytes(buf[:2], 'big')
                return 'clients connected: ' + buf[2 + tlen:].decode('latin1')
        return 'connected and subscribed, but broker sent no $SYS value'
    finally:
        try:
            s.sendall(packet(0xE0, b''))
        except OSError:
            pass
        s.close()


if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.exit(f'usage: {sys.argv[0]} <host> [host ...]')
    for host in sys.argv[1:]:
        try:
            print(f'{host:16} {probe(host)}')
        except Exception as e:
            print(f'{host:16} {type(e).__name__}: {e}')
