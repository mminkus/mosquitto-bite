#!/usr/bin/env python3
"""
uboot_interrupt.py — power-cycle the AP11000 via its Kasa HS103 smartplug and
flood the UART with abort characters to catch the 1-second U-Boot autoboot window.

Pure stdlib: talks the legacy TP-Link Kasa protocol (TCP/9999, autokey-XOR) and
drives the serial port via termios. No pip packages needed.

Usage:
    ./uboot_interrupt.py interrupt      # the main event: cycle power + flood, then go interactive
    ./uboot_interrupt.py query          # dump plug sysinfo
    ./uboot_interrupt.py on | off       # relay control
    ./uboot_interrupt.py monitor        # just read the serial port (like screen, read-only)

Key flags for `interrupt`:
    --flood-secs 8       how long to hammer the abort key after power-on
    --off-secs 2         how long to hold power off (let caps drain)
    --key csp            abort key: csp (this board's compiled-in default stop string) |
                         ctrlc | space | enter | esc | a | any literal string (repeatable/comma-list)
    --no-interactive     don't drop into the interactive bridge even on a TTY

Interactive bridge: once a U-Boot prompt is detected (or the flood ends) and you're
on a real terminal, keystrokes pass through to the AP. Exit with Ctrl-] .
"""
import argparse
import json
import os
import select
import socket
import struct
import sys
import termios
import time
import tty

PLUG_IP = "10.2.4.63"
PLUG_PORT = 9999
SERIAL_PORT = "/dev/cu.usbserial-A50285BI"
BAUD = 115200

# U-Boot prompts seen on QCA/IPQ vendor builds. Detection is best-effort.
PROMPT_MARKERS = (b"IPQ5332#", b"IPQ5322#", b"(IPQ) #", b"IPQ# ", b"=> ", b"\r\n# ")
ABORT_MARKER = b"stop autoboot"

KEY_BYTES = {
    "csp": b"csp",   # this board's compiled-in default CONFIG_AUTOBOOT stop string
                     # (bootstopkey/bootdelaykey unset -> fallback "csp", confirmed by disasm)
    "ctrlc": b"\x03",
    "space": b" ",
    "enter": b"\r",
    "esc": b"\x1b",
    "a": b"a",
}


# ----------------------------- Kasa (TCP/9999) -----------------------------
def _kasa_encrypt(payload: str) -> bytes:
    key = 171
    out = bytearray()
    for c in payload.encode():
        key ^= c
        out.append(key)
    return struct.pack(">I", len(out)) + bytes(out)


def _kasa_decrypt(data: bytes) -> str:
    key = 171
    out = bytearray()
    for c in data:
        out.append(key ^ c)
        key = c
    return bytes(out).decode(errors="replace")


def kasa_cmd(obj: dict, timeout: float = 4.0) -> dict:
    s = socket.create_connection((PLUG_IP, PLUG_PORT), timeout=timeout)
    try:
        s.sendall(_kasa_encrypt(json.dumps(obj)))
        # length-prefixed response
        hdr = b""
        while len(hdr) < 4:
            chunk = s.recv(4 - len(hdr))
            if not chunk:
                break
            hdr += chunk
        n = struct.unpack(">I", hdr)[0] if len(hdr) == 4 else 4096
        body = b""
        while len(body) < n:
            chunk = s.recv(n - len(body))
            if not chunk:
                break
            body += chunk
    finally:
        s.close()
    return json.loads(_kasa_decrypt(body))


def plug_set(state: int) -> None:
    kasa_cmd({"system": {"set_relay_state": {"state": state}}})


def plug_query() -> dict:
    return kasa_cmd({"system": {"get_sysinfo": {}}})


# ------------------------------- Serial ------------------------------------
def open_serial() -> int:
    fd = os.open(SERIAL_PORT, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    attrs = termios.tcgetattr(fd)
    iflag, oflag, cflag, lflag, ispeed, ospeed, cc = attrs
    iflag &= ~(termios.IGNBRK | termios.BRKINT | termios.PARMRK | termios.ISTRIP
               | termios.INLCR | termios.IGNCR | termios.ICRNL | termios.IXON
               | termios.IXOFF)
    oflag &= ~termios.OPOST
    lflag &= ~(termios.ECHO | termios.ECHONL | termios.ICANON | termios.ISIG
               | termios.IEXTEN)
    cflag &= ~(termios.CSIZE | termios.PARENB | termios.CSTOPB)
    cflag |= termios.CS8 | termios.CREAD | termios.CLOCAL
    crtscts = getattr(termios, "CRTSCTS", 0)
    if crtscts:
        cflag &= ~crtscts
    speed = termios.B115200
    termios.tcsetattr(
        fd, termios.TCSANOW,
        [iflag, oflag, cflag, lflag, speed, speed, cc],
    )
    termios.tcflush(fd, termios.TCIOFLUSH)
    return fd


def write_all(fd: int, data: bytes) -> None:
    while data:
        try:
            n = os.write(fd, data)
            data = data[n:]
        except BlockingIOError:
            select.select([], [fd], [], 0.05)


def parse_keys(spec: str) -> bytes:
    if spec.strip().lower() in ("none", ""):
        return b""  # no injected bytes — power-cycle + watch only (for button/GPIO tests)
    out = bytearray()
    for name in spec.split(","):
        name = name.strip().lower()
        if name in KEY_BYTES:
            out += KEY_BYTES[name]
        else:
            out += name.encode()  # any other token = literal string, sent as-is
    return bytes(out)


# ------------------------------- Commands ----------------------------------
def cmd_query(_args) -> None:
    info = plug_query()["system"]["get_sysinfo"]
    keys = ("alias", "model", "hw_ver", "sw_ver", "mac", "relay_state", "on_time", "rssi")
    for k in keys:
        if k in info:
            print(f"{k:12} {info[k]}")


def cmd_on(_args) -> None:
    plug_set(1)
    print("plug ON")


def cmd_off(_args) -> None:
    plug_set(0)
    print("plug OFF")


def cmd_monitor(_args) -> None:
    fd = open_serial()
    print(f"[monitor] reading {SERIAL_PORT} @ {BAUD}. Ctrl-C to quit.", file=sys.stderr)
    try:
        while True:
            r, _, _ = select.select([fd], [], [], 1.0)
            if fd in r:
                data = os.read(fd, 4096)
                if data:
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
    except KeyboardInterrupt:
        pass
    finally:
        os.close(fd)


def interactive_bridge(fd: int) -> None:
    """Pass stdin<->serial until Ctrl-] . Requires a real TTY on stdin."""
    if not sys.stdin.isatty():
        print("\n[bridge] stdin is not a TTY; skipping interactive mode.", file=sys.stderr)
        return
    print("\n[bridge] interactive. Exit with Ctrl-] .", file=sys.stderr)
    stdin_fd = sys.stdin.fileno()
    old = termios.tcgetattr(stdin_fd)
    try:
        tty.setraw(stdin_fd)
        while True:
            r, _, _ = select.select([fd, stdin_fd], [], [], 0.2)
            if fd in r:
                data = os.read(fd, 4096)
                if data:
                    os.write(1, data)
            if stdin_fd in r:
                data = os.read(stdin_fd, 4096)
                if b"\x1d" in data:  # Ctrl-]
                    data = data.split(b"\x1d")[0]
                    if data:
                        write_all(fd, data)
                    break
                write_all(fd, data)
    finally:
        termios.tcsetattr(stdin_fd, termios.TCSANOW, old)
        print("\n[bridge] closed.", file=sys.stderr)


def cmd_interrupt(args) -> None:
    abort = parse_keys(args.key)
    fd = open_serial()
    print(f"[serial] {SERIAL_PORT} @ {BAUD} open", file=sys.stderr)

    print(f"[plug] powering OFF for {args.off_secs}s ...", file=sys.stderr)
    plug_set(0)
    time.sleep(args.off_secs)

    if abort:
        print(f"[plug] powering ON; flooding abort key {abort!r} for {args.flood_secs}s ...",
              file=sys.stderr)
    else:
        print(f"[plug] powering ON; NOT injecting any bytes, watching for {args.flood_secs}s "
              f"(button/GPIO test mode) ...", file=sys.stderr)
    plug_set(1)

    seen = bytearray()
    prompt_hit = False
    abort_seen = False
    stop_flood_at = None   # set once the abort banner appears; stop spraying soon after
    deadline = time.monotonic() + args.flood_secs
    last_write = 0.0

    while time.monotonic() < deadline:
        # hammer the abort key ~50x/sec; no newline is sent, so nothing executes.
        # U-Boot does a rolling tail-compare of the last chars vs the stop string,
        # so repeating "csp" matches on each cycle.
        now = time.monotonic()
        flooding = abort and (stop_flood_at is None or now < stop_flood_at)
        if flooding and now - last_write >= 0.02:
            write_all(fd, abort)
            last_write = now
        r, _, _ = select.select([fd], [], [], 0.02)
        if fd in r:
            data = os.read(fd, 4096)
            if data:
                sys.stdout.buffer.write(data)
                sys.stdout.buffer.flush()
                seen += data
                seen = seen[-4096:]
                if not abort_seen and ABORT_MARKER in seen:
                    abort_seen = True
                    # The match lands within the ~1s window; keep flooding briefly
                    # to guarantee the tail-match, then stop so we don't type junk
                    # into the live U-Boot prompt.
                    stop_flood_at = now + 1.2
                if any(m in seen for m in PROMPT_MARKERS) or seen.rstrip().endswith(b"#"):
                    prompt_hit = True
                    break

    sys.stdout.buffer.flush()
    print("", file=sys.stderr)
    if prompt_hit:
        print("[result] U-Boot prompt DETECTED — abort succeeded.", file=sys.stderr)
    else:
        print("[result] no U-Boot prompt detected in the flood window.", file=sys.stderr)
        if abort_seen:
            print("         (saw the 'stop autoboot' banner and flooded the stop key. "
                  "Serial RX is known-good, so this is most likely a timing miss on the ~1s "
                  "window or a prompt string we didn't recognize — just re-run interrupt. "
                  "If it never catches, scroll up: did a '#' prompt appear at all?)",
                  file=sys.stderr)
        else:
            print("         (never even saw the boot banner — check power/serial; "
                  "was the plug actually driving the AP?)", file=sys.stderr)

    if args.no_interactive:
        os.close(fd)
        return
    # Whether or not we detected the prompt, hand over the live port so the user
    # can poke at it (send Enter, printenv, etc.).
    if prompt_hit:
        write_all(fd, b"\r")
    interactive_bridge(fd)
    os.close(fd)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("query", help="dump plug sysinfo").set_defaults(func=cmd_query)
    sub.add_parser("on", help="relay on").set_defaults(func=cmd_on)
    sub.add_parser("off", help="relay off").set_defaults(func=cmd_off)
    sub.add_parser("monitor", help="read serial only").set_defaults(func=cmd_monitor)

    pi = sub.add_parser("interrupt", help="power-cycle + flood abort key")
    pi.add_argument("--flood-secs", type=float, default=8.0)
    pi.add_argument("--off-secs", type=float, default=2.0)
    pi.add_argument("--key", default="csp",
                    help="abort key(s), comma list. Default 'csp' = this board's compiled-in "
                         "stop string. Also: ctrlc,space,enter,esc,a or any literal string.")
    pi.add_argument("--no-interactive", action="store_true")
    pi.set_defaults(func=cmd_interrupt)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
