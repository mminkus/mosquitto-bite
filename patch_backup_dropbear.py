#!/usr/bin/env python3
import argparse
import io
import stat
import tarfile
import time
from pathlib import Path


BEGIN_MARKER = "# BEGIN local dropbear persistence"
END_MARKER = "# END local dropbear persistence"


DROPBEAR_BLOCK = f"""{BEGIN_MARKER}
mkdir -p /etc/dropbear /var/run
chown root:root /etc/dropbear 2>/dev/null || true
chmod 700 /etc/dropbear
for key in /etc/dropbear/dropbear_rsa_host_key /etc/dropbear/dropbear_ed25519_host_key; do
    [ -s "$key" ] || rm -f "$key"
done
chown root:root /etc/dropbear/authorized_keys 2>/dev/null || true
chmod 600 /etc/dropbear/authorized_keys 2>/dev/null || true
[ -x /usr/sbin/dropbear ] && /usr/sbin/dropbear -R -s -p 22 -P /var/run/dropbear-local.pid >/tmp/dropbear-local.log 2>&1 || true
{END_MARKER}
"""


BAD_MOD_RANGE = range(1000, 1024)


def normalize_tar_name(name):
    return name[2:] if name.startswith("./") else name


def clean_public_key(path):
    lines = []
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            lines.append(stripped)
    if not lines:
        raise SystemExit(f"no public key found in {path}")
    return ("\n".join(lines) + "\n").encode()


def strip_existing_block(text):
    while BEGIN_MARKER in text and END_MARKER in text:
        start = text.index(BEGIN_MARKER)
        end = text.index(END_MARKER, start) + len(END_MARKER)
        if end < len(text) and text[end : end + 1] == "\n":
            end += 1
        text = text[:start].rstrip() + "\n" + text[end:].lstrip()
    return text


def patch_rc_local(data):
    text = data.decode("utf-8", "replace")
    text = strip_existing_block(text)
    lines = text.splitlines()
    exit_index = None
    for index, line in enumerate(lines):
        if line.strip() == "exit 0":
            exit_index = index
            break
    block_lines = DROPBEAR_BLOCK.rstrip().splitlines()
    if exit_index is None:
        lines.extend(["", *block_lines, "exit 0"])
    else:
        lines[exit_index:exit_index] = ["", *block_lines]
    return ("\n".join(lines).rstrip() + "\n").encode()


def make_regular_info(name, size, mode, mtime):
    info = tarfile.TarInfo(name)
    info.size = size
    info.mode = mode
    info.mtime = mtime
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    return info


def build_tar(input_tar, output_tar, public_key, padding_size):
    now = int(time.time())
    with tarfile.open(input_tar, "r:gz") as source, tarfile.open(output_tar, "w:gz") as target:
        rc_data = None
        for member in source.getmembers():
            name = normalize_tar_name(member.name)
            if name == "etc/rc.local" and member.isfile():
                existing = source.extractfile(member)
                if existing is not None:
                    rc_data = existing.read()
                continue
            if name in {"etc/dropbear/authorized_keys", "etc/dropbear/.local_dropbear_padding"}:
                continue
            fileobj = source.extractfile(member) if member.isfile() else None
            member.name = name
            target.addfile(member, fileobj)

        if rc_data is None:
            rc_data = b"# Put your custom commands here that should be executed once\n# the system init finished.\n\nexit 0\n"
        rc_data = patch_rc_local(rc_data)
        rc_info = make_regular_info("etc/rc.local", len(rc_data), 0o755, now)
        target.addfile(rc_info, io.BytesIO(rc_data))

        key_info = make_regular_info("etc/dropbear/authorized_keys", len(public_key), 0o600, now)
        target.addfile(key_info, io.BytesIO(public_key))

        if padding_size:
            padding = b"x" * padding_size
            pad_info = make_regular_info("etc/dropbear/.local_dropbear_padding", len(padding), 0o600, now)
            target.addfile(pad_info, io.BytesIO(padding))


def build_with_safe_size(input_tar, output_tar, public_key):
    for padding_size in range(0, 4096):
        build_tar(input_tar, output_tar, public_key, padding_size)
        if output_tar.stat().st_size % 1024 not in BAD_MOD_RANGE:
            return padding_size
    raise SystemExit("could not produce tar.gz outside Cudy crypt bad final-chunk range")


def inspect_output(path):
    with tarfile.open(path, "r:gz") as archive:
        names = {normalize_tar_name(member.name): member for member in archive.getmembers()}
        required = ["etc/rc.local", "etc/dropbear/authorized_keys"]
        missing = [name for name in required if name not in names]
        if missing:
            raise SystemExit(f"patched archive missing required entries: {', '.join(missing)}")
        rc_member = names["etc/rc.local"]
        key_member = names["etc/dropbear/authorized_keys"]
        if not stat.S_IMODE(rc_member.mode) & stat.S_IXUSR:
            raise SystemExit("etc/rc.local is not owner-executable")
        if stat.S_IMODE(key_member.mode) != 0o600:
            raise SystemExit("etc/dropbear/authorized_keys mode is not 0600")


def main():
    parser = argparse.ArgumentParser(description="Patch a Cudy config-backup tar.gz to start dropbear with key-only root auth.")
    parser.add_argument("-i", "--input", required=True, type=Path, help="input decrypted backup tar.gz")
    parser.add_argument("-o", "--output", required=True, type=Path, help="output patched backup tar.gz")
    parser.add_argument("-k", "--pubkey", required=True, type=Path, help="SSH public key to install")
    args = parser.parse_args()

    public_key = clean_public_key(args.pubkey)
    padding_size = build_with_safe_size(args.input, args.output, public_key)
    inspect_output(args.output)
    print(f"wrote {args.output} ({args.output.stat().st_size} bytes, padding={padding_size})")


if __name__ == "__main__":
    main()
