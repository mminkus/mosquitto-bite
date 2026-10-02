#!/usr/bin/env python3
import argparse
import hashlib
import os
import struct
import subprocess
import sys
import time
from pathlib import Path


MAGIC = 0xA1ECD5BD
DEFAULT_RANDOM = 0x0FAA92AB
CHUNK_SIZE = 0x400
HEADER_SIZE = 0x30
ZERO_IV = "00" * 16


class CryptError(Exception):
    pass


def run_openssl(arguments, data):
    process = subprocess.run(
        ["openssl", "enc", *arguments],
        input=data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if process.returncode != 0:
        message = process.stderr.decode("utf-8", "replace").strip()
        raise CryptError(f"openssl failed: {message}")
    return process.stdout


def aes_cbc_encrypt_full_blocks(key_hex, data):
    if not data:
        return b""
    return run_openssl(
        ["-aes-128-cbc", "-K", key_hex, "-iv", ZERO_IV, "-nosalt", "-nopad"],
        data,
    )


def aes_cbc_decrypt_full_blocks(key_hex, data):
    if not data:
        return b""
    return run_openssl(
        ["-d", "-aes-128-cbc", "-K", key_hex, "-iv", ZERO_IV, "-nosalt", "-nopad"],
        data,
    )


def aes_ecb_encrypt_block(key_hex, block):
    return run_openssl(["-aes-128-ecb", "-K", key_hex, "-nosalt", "-nopad"], block)


def aes_ecb_decrypt_block(key_hex, block):
    return run_openssl(["-d", "-aes-128-ecb", "-K", key_hex, "-nosalt", "-nopad"], block)


def cbc_encrypt_raw(key_hex, data):
    full_length = len(data) & ~0xF
    remainder = len(data) - full_length
    output = bytearray(aes_cbc_encrypt_full_blocks(key_hex, data[:full_length]))
    if remainder:
        ivec = bytes(output[-16:]) if output else b"\x00" * 16
        partial_block = bytearray(ivec)
        for index, value in enumerate(data[full_length:]):
            partial_block[index] ^= value
        output.extend(aes_ecb_encrypt_block(key_hex, bytes(partial_block))[:remainder])
    return bytes(output)


def cbc_decrypt_raw(key_hex, data):
    full_length = len(data) & ~0xF
    remainder = len(data) - full_length
    output = bytearray(aes_cbc_decrypt_full_blocks(key_hex, data[:full_length]))
    if remainder:
        ivec = data[full_length - 16 : full_length] if full_length else b"\x00" * 16
        padded_ciphertext = data[full_length:] + (b"\x00" * (16 - remainder))
        decrypted_block = aes_ecb_decrypt_block(key_hex, padded_ciphertext)
        output.extend(decrypted_block[index] ^ ivec[index] for index in range(remainder))
    return bytes(output)


def normalize_key_hex(key_hex):
    value = key_hex.strip().lower()
    if len(value) != 32:
        raise CryptError("AES-128 key must be 32 hex characters")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise CryptError("AES key is not valid hex") from exc
    return value


def env_value(name):
    value = os.environ.get(name)
    return value if value else None


def resolve_key(args):
    key_hex = args.key_hex or env_value(args.key_env)
    if key_hex:
        return normalize_key_hex(key_hex)

    secret = args.secret or env_value(args.secret_env)
    if args.standard_aes:
        if not args.board:
            raise CryptError("--board is required for -a key derivation unless --key-hex is used")
        key_string = f"{args.board}@aes#hex"
    elif args.global_key:
        if secret is None:
            raise CryptError(f"--secret or ${args.secret_env} is required for -g unless --key-hex is used")
        key_string = f"@{secret}"
    else:
        if secret is None:
            raise CryptError(f"--secret or ${args.secret_env} is required unless --key-hex is used")
        hostname = args.hostname or os.environ.get(args.hostname_env)
        if not hostname:
            raise CryptError(f"--hostname or ${args.hostname_env} is required unless --key-hex is used")
        key_string = f"{hostname}@{secret}"

    return hashlib.md5(key_string.encode()).hexdigest()


def rom_version_bytes(version):
    encoded = version.encode("utf-8", "replace")[:31]
    return encoded + (b"\x00" * (32 - len(encoded)))


def make_header(args):
    timestamp = args.timestamp if args.timestamp is not None else int(time.time())
    random_value = args.random if args.random is not None else DEFAULT_RANDOM
    return (
        struct.pack("<IIII", MAGIC, timestamp & 0xFFFFFFFF, random_value & 0xFFFFFFFF, 0)
        + rom_version_bytes(args.rom_version)
    )


def parse_header(header_plaintext):
    if len(header_plaintext) != HEADER_SIZE:
        raise CryptError("decrypted header has invalid length")
    magic, timestamp, random_value, reserved = struct.unpack("<IIII", header_plaintext[:16])
    version = header_plaintext[16:].split(b"\x00", 1)[0].decode("utf-8", "replace")
    if magic != MAGIC:
        raise CryptError(f"bad magic 0x{magic:08x}")
    return {
        "timestamp": timestamp,
        "random": random_value,
        "reserved": reserved,
        "version": version,
    }


def encrypt_cudy_file(key_hex, input_path, output_path, args):
    with input_path.open("rb") as input_file, output_path.open("wb") as output_file:
        output_file.write(cbc_encrypt_raw(key_hex, make_header(args)))
        while True:
            chunk = input_file.read(CHUNK_SIZE)
            if not chunk:
                break
            if len(chunk) < CHUNK_SIZE:
                remainder = len(chunk) & 0xF
                plain_length = len(chunk) + remainder + 0x10
                padded_chunk = bytearray(plain_length)
                padded_chunk[: len(chunk)] = chunk
                padded_chunk[len(chunk) + remainder] = remainder
                output_file.write(cbc_encrypt_raw(key_hex, bytes(padded_chunk)))
            else:
                output_file.write(cbc_encrypt_raw(key_hex, chunk))


def decrypt_cudy_file(key_hex, input_path, output_path, args):
    with input_path.open("rb") as input_file, output_path.open("wb") as output_file:
        encrypted_header = input_file.read(HEADER_SIZE)
        if len(encrypted_header) != HEADER_SIZE:
            raise CryptError("input is too short for a Cudy crypt header")
        header = parse_header(cbc_decrypt_raw(key_hex, encrypted_header))
        if args.show_header:
            print(
                "header: "
                f"timestamp={header['timestamp']} "
                f"random=0x{header['random']:08x} "
                f"version={header['version']}",
                file=sys.stderr,
            )

        while True:
            encrypted_chunk = input_file.read(CHUNK_SIZE)
            if not encrypted_chunk:
                break
            decrypted_chunk = cbc_decrypt_raw(key_hex, encrypted_chunk)
            if len(encrypted_chunk) >= CHUNK_SIZE:
                output_file.write(decrypted_chunk[: len(encrypted_chunk)])
                continue
            if len(encrypted_chunk) <= 0x10:
                write_length = len(encrypted_chunk)
            else:
                write_length = len(encrypted_chunk) - 0x10
                marker = decrypted_chunk[write_length]
                if marker <= write_length:
                    write_length -= marker
            output_file.write(decrypted_chunk[:write_length])


def encrypt_standard_aes(key_hex, input_path, output_path):
    data = input_path.read_bytes()[:CHUNK_SIZE]
    padded_length = (len(data) & ~0xF) + 0x10
    padded = data + (b"\x00" * (padded_length - len(data)))
    output_path.write_bytes(cbc_encrypt_raw(key_hex, padded).hex().upper().encode())


def decrypt_standard_aes(key_hex, input_path, output_path):
    hex_data = b"".join(input_path.read_bytes()[:0x820].split())
    ciphertext = bytes.fromhex(hex_data.decode())
    plaintext = cbc_decrypt_raw(key_hex, ciphertext)
    output_path.write_bytes(plaintext.split(b"\x00", 1)[0])


def build_parser():
    parser = argparse.ArgumentParser(
        description="Local implementation of Cudy AP11000 /usr/bin/crypt default, -g, and -a modes."
    )
    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument("-e", "--encrypt", action="store_true", help="encrypt input")
    operation.add_argument("-d", "--decrypt", action="store_true", help="decrypt input")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("-a", "--standard-aes", action="store_true", help="Cudy standard AES/hex mode")
    mode.add_argument("-g", "--global-key", action="store_true", help="Cudy global key mode")
    parser.add_argument("-i", "--input", required=True, type=Path, help="input file")
    parser.add_argument("-o", "--output", required=True, type=Path, help="output file")
    parser.add_argument("--key-hex", help="raw AES-128 key as 32 hex characters")
    parser.add_argument("--key-env", default="CUDY_AES_KEY", help="environment variable containing AES key")
    parser.add_argument("--secret", help="bdinfo secret value for derived-key modes")
    parser.add_argument("--secret-env", default="CUDY_BDINFO_SECRET", help="environment variable containing bdinfo secret")
    parser.add_argument("--hostname", help="device hostname for normal derived-key mode")
    parser.add_argument("--hostname-env", default="CUDY_HOSTNAME", help="environment variable containing hostname")
    parser.add_argument("--board", help="bdinfo board value for -a derived-key mode")
    parser.add_argument("--rom-version", default="2.2.19-20250416-085906", help="version string embedded on encrypt")
    parser.add_argument("--timestamp", type=int, help="header timestamp for deterministic encryption")
    parser.add_argument("--random", type=lambda value: int(value, 0), help="header random field for deterministic encryption")
    parser.add_argument("--show-header", action="store_true", help="print decrypted header metadata to stderr")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        key_hex = resolve_key(args)
        if args.standard_aes:
            if args.encrypt:
                encrypt_standard_aes(key_hex, args.input, args.output)
            else:
                decrypt_standard_aes(key_hex, args.input, args.output)
        elif args.encrypt:
            encrypt_cudy_file(key_hex, args.input, args.output, args)
        else:
            decrypt_cudy_file(key_hex, args.input, args.output, args)
    except (CryptError, OSError, ValueError) as exc:
        parser.exit(1, f"cudy_crypt.py: error: {exc}\n")


if __name__ == "__main__":
    main()
