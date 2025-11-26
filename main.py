#!/usr/bin/env python3
"""
secure_vault.py

Single script that consolidates configuration handling, machine fingerprinting,
and vault encryption. It avoids import-time prompts, works on non-Windows hosts,
and surfaces clear error messages when configuration fails.
"""

import argparse
import base64
import getpass
import hashlib
import hmac
import json
import os
import platform
import secrets
import subprocess
import sys
import uuid
from datetime import datetime
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CONFIG_FILE = Path("config.obf")
VAULT_FILE = Path("secure_vault.dat")
DEFAULT_PBKDF2_ITERATIONS = 700_000


def _derive_key(master_secret: str) -> bytes:
    return hashlib.sha256(master_secret.encode("utf-8")).digest()


def _obfuscate(plain: str, master_secret: str, offset: int = 17) -> str:
    key = _derive_key(master_secret)
    raw = plain.encode("utf-8")
    out = bytearray(len(raw))
    for idx, val in enumerate(raw):
        out[idx] = ((val ^ key[idx % len(key)]) + offset) & 0xFF
    return out.hex()


def _deobfuscate(hex_value: str, master_secret: str, offset: int = 17) -> str:
    key = _derive_key(master_secret)
    raw = bytes.fromhex(hex_value)
    out = bytearray(len(raw))
    for idx, val in enumerate(raw):
        out[idx] = ((val - offset) & 0xFF) ^ key[idx % len(key)]
    return out.decode("utf-8")


def save_config(pepper: str, iterations: int, machine_binding: bool, master_secret: str, offset: int = 17) -> None:
    payload = {
        "pepper": _obfuscate(pepper, master_secret, offset),
        "iterations": _obfuscate(str(iterations), master_secret, offset),
        "machine_binding": _obfuscate("1" if machine_binding else "0", master_secret, offset),
        "offset": offset,
    }
    tmp = CONFIG_FILE.with_suffix(CONFIG_FILE.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    os.replace(tmp, CONFIG_FILE)
    CONFIG_FILE.chmod(0o600)


def load_config(master_secret: str) -> dict:
    if not CONFIG_FILE.exists():
        raise FileNotFoundError("Missing config.obf; run init-config to create it.")
    try:
        data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError("Config file is corrupted or not valid JSON.") from exc

    try:
        offset = int(data.get("offset", 17))
        pepper = _deobfuscate(data["pepper"], master_secret, offset)
        iterations = int(_deobfuscate(data["iterations"], master_secret, offset))
        machine_binding = bool(int(_deobfuscate(data["machine_binding"], master_secret, offset)))
    except KeyError as exc:
        raise ValueError(f"Config is missing required field: {exc}") from exc
    except Exception as exc:
        raise ValueError("Incorrect master secret or corrupted config contents.") from exc

    if iterations <= 0:
        raise ValueError("PBKDF2 iterations must be a positive integer.")

    return {
        "pepper": pepper,
        "iterations": iterations,
        "machine_binding": machine_binding,
        "offset": offset,
    }


def prompt_master_secret(env_name: str = "MASTER_SECRET") -> str:
    env_val = os.environ.get(env_name)
    if env_val:
        return env_val
    secret = getpass.getpass("Enter master secret (used to unlock config): ").strip()
    if not secret:
        raise RuntimeError("Master secret is required for this operation.")
    return secret


def init_config(master_secret: str, args: argparse.Namespace) -> dict:
    pepper = args.pepper or os.environ.get("AUTH_PEPPER") or secrets.token_hex(32)
    iterations = args.iterations or int(os.environ.get("PBKDF2_ITERS", DEFAULT_PBKDF2_ITERATIONS))
    machine_binding = args.bind_machine
    save_config(pepper, iterations, machine_binding, master_secret)
    print(f"[+] Config saved to {CONFIG_FILE} (machine binding={'on' if machine_binding else 'off'}).")
    return {
        "pepper": pepper,
        "iterations": iterations,
        "machine_binding": machine_binding,
        "offset": 17,
    }


def ensure_config(args: argparse.Namespace) -> tuple[dict, str]:
    master_secret = args.master_secret or prompt_master_secret()
    try:
        config = load_config(master_secret)
        return config, master_secret
    except FileNotFoundError:
        if args.command != "init-config":
            print("Config not found; running init-config flow.")
        config = init_config(master_secret, args)
        return config, master_secret
    except ValueError as exc:
        print(f"Config error: {exc}")
        sys.exit(1)
    except RuntimeError as exc:
        print(exc)
        sys.exit(1)


# ----------------------
# Machine fingerprinting
# ----------------------

def _powershell(command: str) -> str | None:
    try:
        output = subprocess.check_output(
            ["powershell", "-Command", command], stderr=subprocess.DEVNULL, timeout=2
        )
        text = output.decode().strip()
        return text or None
    except (FileNotFoundError, subprocess.SubprocessError, subprocess.TimeoutExpired):
        return None


def _linux_machine_id() -> str | None:
    for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            content = Path(path).read_text().strip()
            if content:
                return content
        except (FileNotFoundError, PermissionError):
            continue
    return None


def get_machine_fingerprint(bind: bool) -> bytes:
    if not bind:
        return b"portable"

    values: list[str] = []

    if platform.system().lower() == "windows":
        uuid_val = _powershell("(Get-CimInstance Win32_ComputerSystemProduct).UUID")
        disk_serial = _powershell("(Get-PhysicalDisk).SerialNumber | Select -First 1")
        if uuid_val:
            values.append(uuid_val)
        if disk_serial:
            values.append(disk_serial)

    mac_val = f"{uuid.getnode():012x}"
    if mac_val:
        values.append(mac_val)

    linux_id = _linux_machine_id()
    if linux_id:
        values.append(linux_id)

    hostname = platform.node()
    if hostname:
        values.append(hostname)

    if not values:
        values.append("unknown-machine")

    joined = "|".join(values)
    return hashlib.sha256(joined.encode("utf-8")).digest()


# ----------------------
# Vault primitives
# ----------------------

def derive_vault_key(password: str, pepper: str, iterations: int, machine_binding: bool) -> bytes:
    salt = hashlib.blake2b(pepper.encode("utf-8"), digest_size=16).digest()
    material = (password + pepper).encode("utf-8") + get_machine_fingerprint(machine_binding)
    return hashlib.pbkdf2_hmac("sha256", material, salt, iterations, dklen=32)


def encrypt_payload(data: dict, key: bytes) -> bytes:
    nonce = secrets.token_bytes(12)
    body = json.dumps(data, indent=2, sort_keys=True).encode("utf-8")
    aes = AESGCM(key)
    ciphertext = aes.encrypt(nonce, body, associated_data=None)
    tag = hmac.new(key, nonce + ciphertext, hashlib.sha512).digest()
    return base64.b64encode(nonce + ciphertext + tag)


def decrypt_payload(blob: bytes, key: bytes) -> dict:
    raw = base64.b64decode(blob)
    nonce, rest = raw[:12], raw[12:]
    tag = rest[-64:]
    ciphertext = rest[:-64]
    expected = hmac.new(key, nonce + ciphertext, hashlib.sha512).digest()
    if not hmac.compare_digest(expected, tag):
        raise ValueError("Vault integrity check failed (HMAC mismatch).")
    aes = AESGCM(key)
    plaintext = aes.decrypt(nonce, ciphertext, associated_data=None)
    return json.loads(plaintext.decode("utf-8"))


def load_vault(key: bytes) -> dict:
    if not VAULT_FILE.exists():
        return {"secrets": {}, "updated_at": datetime.utcnow().isoformat()}
    data = decrypt_payload(VAULT_FILE.read_bytes(), key)
    if "secrets" not in data:
        data["secrets"] = {}
    return data


def save_vault(data: dict, key: bytes) -> None:
    data["updated_at"] = datetime.utcnow().isoformat()
    VAULT_FILE.write_bytes(encrypt_payload(data, key))
    VAULT_FILE.chmod(0o600)


# ----------------------
# CLI commands
# ----------------------

def cmd_init_config(args: argparse.Namespace) -> None:
    master_secret = args.master_secret or prompt_master_secret()
    init_config(master_secret, args)


def cmd_set_secret(args: argparse.Namespace) -> None:
    config, _ = ensure_config(args)
    password = args.password or getpass.getpass("Enter vault password: ")
    key = derive_vault_key(password, config["pepper"], config["iterations"], config["machine_binding"])
    vault = load_vault(key)
    secret_value = args.value or getpass.getpass(f"Value for {args.name}: ")
    vault.setdefault("secrets", {})[args.name] = secret_value
    save_vault(vault, key)
    print(f"[+] Stored secret '{args.name}'.")


def cmd_get_secret(args: argparse.Namespace) -> None:
    config, _ = ensure_config(args)
    password = args.password or getpass.getpass("Enter vault password: ")
    key = derive_vault_key(password, config["pepper"], config["iterations"], config["machine_binding"])
    vault = load_vault(key)
    try:
        value = vault["secrets"][args.name]
        print(value)
    except KeyError:
        print(f"Secret '{args.name}' not found.")
        sys.exit(1)


def cmd_list(args: argparse.Namespace) -> None:
    config, _ = ensure_config(args)
    password = args.password or getpass.getpass("Enter vault password: ")
    key = derive_vault_key(password, config["pepper"], config["iterations"], config["machine_binding"])
    vault = load_vault(key)
    if not vault["secrets"]:
        print("No secrets stored.")
        return
    print("Stored secrets:")
    for name in sorted(vault["secrets"].keys()):
        print(f" - {name}")


def cmd_wipe(args: argparse.Namespace) -> None:
    _, master_secret = ensure_config(args)
    confirm = input("Type 'WIPE' to delete the vault file: ").strip()
    if confirm != "WIPE":
        print("Aborted.")
        return
    try:
        VAULT_FILE.unlink()
        print("[+] Vault file deleted.")
    except FileNotFoundError:
        print("Vault file does not exist; nothing to delete.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Secure vault utility (single script).")
    parser.add_argument("--master-secret", dest="master_secret", help="Master secret for config operations.")
    parser.add_argument("--password", dest="password", help="Vault password for non-interactive use.")
    sub = parser.add_subparsers(dest="command", required=True)

    init_p = sub.add_parser("init-config", help="Create or replace the obfuscated config file.")
    init_p.add_argument("--pepper", help="Optional pepper to bake into the config.")
    init_p.add_argument("--iterations", type=int, help="PBKDF2 iterations (defaults to 700k).")
    init_p.add_argument("--bind-machine", action="store_true", help="Bind vault keys to this machine's fingerprint.")
    init_p.set_defaults(func=cmd_init_config)

    set_p = sub.add_parser("set", help="Store or replace a secret in the vault.")
    set_p.add_argument("name", help="Secret name.")
    set_p.add_argument("--value", help="Secret value (use stdin/tty prompt if omitted).")
    set_p.set_defaults(func=cmd_set_secret)

    get_p = sub.add_parser("get", help="Retrieve a secret.")
    get_p.add_argument("name", help="Secret name.")
    get_p.set_defaults(func=cmd_get_secret)

    list_p = sub.add_parser("list", help="List stored secret names.")
    list_p.set_defaults(func=cmd_list)

    wipe_p = sub.add_parser("wipe", help="Delete the vault file after confirmation.")
    wipe_p.set_defaults(func=cmd_wipe)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
