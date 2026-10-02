#!/usr/bin/env python3
"""
Minimal read-only TFTP server for flashing specimen-37 (Cudy AP11000) recovery images.

Purpose-built because the AP11000 factory FIT is ~34 MB, which exceeds the 32 MB
addressable by a 16-bit TFTP block counter at 512-byte blocks. This server:
  * continues past block 65535 by wrapping the *wire* block number to 0 while
    tracking the logical block internally (U-Boot's client handles this rollover),
  * honors RFC 2348 'blksize' and RFC 2349 'tsize' options via OACK when the
    client requests them (a large blksize sidesteps rollover entirely),
  * serves read requests ONLY (no writes), from a single root directory,
  * logs each RRQ / OACK / retransmit / completion so the flash is observable.

Binding UDP port 69 requires root:  sudo python3 tftp_serve.py --root tftproot
"""
import argparse, os, socket, struct, sys, time

OP_RRQ, OP_WRQ, OP_DATA, OP_ACK, OP_ERROR, OP_OACK = 1, 2, 3, 4, 5, 6

def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)

def parse_rrq(payload):
    # filename\0mode\0[opt\0val\0]...
    parts = payload.split(b'\x00')
    fname = parts[0].decode('latin1')
    mode = parts[1].decode('latin1').lower() if len(parts) > 1 else 'octet'
    opts = {}
    rest = parts[2:]
    for i in range(0, len(rest) - 1, 2):
        k = rest[i].decode('latin1').lower()
        v = rest[i + 1].decode('latin1')
        if k:
            opts[k] = v
    return fname, mode, opts

def send_error(sock, addr, code, msg):
    sock.sendto(struct.pack('>HH', OP_ERROR, code) + msg.encode('latin1') + b'\x00', addr)

def serve_file(root, fname, opts, client, listen_ip, retries, timeout):
    safe = os.path.basename(fname)  # no path traversal
    path = os.path.join(root, safe)
    if not os.path.isfile(path):
        log(f"  -> file not found: {safe!r}; sending ERROR")
        return ('notfound', None)
    size = os.path.getsize(path)

    # per-transfer socket on an ephemeral port (standard TFTP behavior)
    xfer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    xfer.bind((listen_ip, 0))
    xfer.settimeout(timeout)

    blksize = 512
    oack = {}
    if 'blksize' in opts:
        try:
            req = int(opts['blksize'])
            blksize = max(8, min(req, 65464))
            oack['blksize'] = str(blksize)
        except ValueError:
            pass
    if 'tsize' in opts:
        oack['tsize'] = str(size)
    if 'timeout' in opts:
        oack['timeout'] = opts['timeout']

    total_blocks = size // blksize + 1  # final (possibly empty) short block
    log(f"  -> serving {safe} ({size} bytes) blksize={blksize} "
        f"total_blocks={total_blocks} rollover={'yes' if total_blocks > 65535 else 'no'}")

    with open(path, 'rb') as f:
        # If any option was accepted, send OACK and expect ACK of block 0.
        if oack:
            pkt = struct.pack('>H', OP_OACK)
            for k, v in oack.items():
                pkt += k.encode('latin1') + b'\x00' + v.encode('latin1') + b'\x00'
            if not _send_await_ack(xfer, pkt, client, 0, retries):
                log("  -> no ACK for OACK; aborting transfer")
                xfer.close(); return ('timeout', None)
            log(f"  -> OACK accepted: {oack}")

        logical = 1
        last_report = time.time()
        while True:
            f.seek((logical - 1) * blksize)
            chunk = f.read(blksize)
            wire = logical & 0xffff
            data_pkt = struct.pack('>HH', OP_DATA, wire) + chunk
            if not _send_await_ack(xfer, data_pkt, client, wire, retries):
                log(f"  -> no ACK for block {logical} (wire {wire}); aborting")
                xfer.close(); return ('timeout', None)
            if time.time() - last_report >= 1.0:
                pct = 100.0 * min((logical * blksize), size) / size if size else 100.0
                log(f"     ...block {logical}/{total_blocks} ({pct:.1f}%)")
                last_report = time.time()
            if len(chunk) < blksize:
                log(f"  -> transfer COMPLETE: {logical} blocks, {size} bytes sent")
                xfer.close(); return ('done', size)
            logical += 1

def _send_await_ack(xfer, pkt, client, expect_wire, retries):
    for attempt in range(retries):
        xfer.sendto(pkt, client)
        try:
            while True:
                data, addr = xfer.recvfrom(4)
                if addr != client:
                    continue
                op, blk = struct.unpack('>HH', data[:4])
                if op == OP_ACK and blk == expect_wire:
                    return True
                if op == OP_ERROR:
                    return False
                # stale/duplicate ACK: ignore, keep waiting within this attempt
        except socket.timeout:
            if attempt + 1 < retries:
                log(f"     timeout waiting ACK {expect_wire}, retransmit {attempt+1}/{retries}")
    return False

def main():
    ap = argparse.ArgumentParser(description="Minimal rollover-safe read-only TFTP server")
    ap.add_argument('--root', default='tftproot', help='directory to serve (default: tftproot)')
    ap.add_argument('--ip', default='0.0.0.0', help='listen IP (default: 0.0.0.0; use 192.168.1.88 to bind the recovery iface)')
    ap.add_argument('--port', type=int, default=69)
    ap.add_argument('--retries', type=int, default=5)
    ap.add_argument('--timeout', type=float, default=2.0)
    ap.add_argument('--once', action='store_true', help='exit after one completed transfer')
    args = ap.parse_args()

    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        sys.exit(f"root dir not found: {root}")

    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((args.ip, args.port))
    except PermissionError:
        sys.exit(f"cannot bind {args.ip}:{args.port} (port <1024 needs sudo)")
    log(f"TFTP server up on {args.ip}:{args.port}, root={root}")
    log(f"files: {', '.join(os.listdir(root)) or '(empty)'}")

    listen_ip = args.ip if args.ip != '0.0.0.0' else ''
    try:
        while True:
            data, client = srv.recvfrom(2048)
            op = struct.unpack('>H', data[:2])[0]
            if op == OP_WRQ:
                log(f"WRQ from {client} -> refused (read-only server)")
                send_error(srv, client, 2, "server is read-only")
                continue
            if op != OP_RRQ:
                continue
            fname, mode, opts = parse_rrq(data[2:])
            log(f"RRQ from {client}: file={fname!r} mode={mode} opts={opts}")
            # bind transfer socket to the same local IP the request arrived on
            bind_ip = listen_ip or client[0].rsplit('.', 1)[0] + '.88'
            result, _ = serve_file(root, fname, opts, client,
                                   listen_ip or '0.0.0.0', args.retries, args.timeout)
            if result == 'notfound':
                send_error(srv, client, 1, "file not found")
            if args.once and result == 'done':
                log("--once: transfer done, exiting")
                break
    except KeyboardInterrupt:
        log("interrupted, shutting down")
    finally:
        srv.close()

if __name__ == '__main__':
    main()
