import os
import json
import hmac
import uuid
import hashlib
import secrets
import subprocess
import time
import keyring
import getpass

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ======================================================================
# CONFIG
# ======================================================================

APP_NAME = "YuviSecureVault"
MASTER_KEY_NAME = "master_key_256bit"
PBKDF2_BASE_ITERATIONS = 670_000   # base cost
MIN_PBKDF_MULTIPLIER = 1.0         # do not allow weaker settings than the base
VAULT_FILE = "yuvi_vault.dat"


# ======================================================================
# MACHINE IDENTIFIERS (Windows)
# ======================================================================

def get_mac() -> str:
    """Return MAC as 12-char hex string."""
    try:
        mac = uuid.getnode()
        return f"{mac:012x}"
    except Exception:
        return "MAC_FAIL"


def get_system_uuid() -> str:
    """Windows system UUID via PowerShell. Falls back if it fails."""
    try:
        output = subprocess.check_output(
            ["powershell", "-Command",
             "(Get-CimInstance Win32_ComputerSystemProduct).UUID"],
            stderr=subprocess.DEVNULL,
        )
        value = output.decode().strip()
        return value if value else "UUID_NOT_FOUND"
    except Exception:
        return "UUID_FAIL"


def get_disk_serial() -> str:
    """First physical disk serial via PowerShell. Safe fallback."""
    try:
        output = subprocess.check_output(
            ["powershell", "-Command",
             "(Get-PhysicalDisk).SerialNumber"],
            stderr=subprocess.DEVNULL,
        )
        lines = [l.strip() for l in output.decode().split("\n") if l.strip()]
        return lines[0] if lines else "DISK_NOT_FOUND"
    except Exception:
        return "DISK_FAIL"


def get_machine_fingerprint() -> bytes:
    """
    Stable, machine-bound fingerprint:
    sha256(UUID | MAC | DISK_SERIAL) -> 32 bytes
    """
    uuid_str = get_system_uuid()
    mac_str = get_mac()
    disk_str = get_disk_serial()
    identifiers = (uuid_str, mac_str, disk_str)
    if any(val.endswith(("FAIL", "NOT_FOUND")) for val in identifiers):
        raise RuntimeError("Unable to obtain stable machine identifiers; aborting to avoid weak binding.")
    combo = f"{uuid_str}|{mac_str}|{disk_str}".encode("utf-8")
    return hashlib.sha256(combo).digest()


# ======================================================================
# MASTER KEY MANAGEMENT (keyring → Credential Locker / DPAPI-backed)
# ======================================================================

def get_or_create_master_key() -> bytes:
    """
    Fetch master key from keyring, or create + store it on first run.
    Stored as hex string; in memory it's raw 32 bytes.
    """
    stored = keyring.get_password(APP_NAME, MASTER_KEY_NAME)

    if stored is None:
        master_key = secrets.token_bytes(32)  # 256-bit
        keyring.set_password(APP_NAME, MASTER_KEY_NAME, master_key.hex())
        print("[+] Created new master key and stored in keyring.")
        return master_key

    master_key = bytes.fromhex(stored)
    if len(master_key) != 32:
        raise ValueError("Stored master key is not 256 bits.")
    print("[+] Loaded existing master key from keyring.")
    return master_key


# ======================================================================
# DERIVATION: AES KEY + PEPPER
# ======================================================================

def derive_aes_key(master_key: bytes, salt: bytes, machine_fp: bytes) -> bytes:
    """
    HKDF-SHA256 -> 32-byte AES key, bound to machine_fp.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"yuvi-secure-vault|" + machine_fp,
        backend=default_backend(),
    )
    return hkdf.derive(master_key)


def derive_pepper(master_key: bytes, machine_fp: bytes) -> bytes:
    """
    Deterministic pepper derived from master_key + machine_fp via HMAC-SHA256.
    Not stored; recomputed each time.
    """
    return hmac.new(master_key, b"pepper|" + machine_fp, hashlib.sha256).digest()


# ======================================================================
# VAULT ENCRYPTION (AES-256-GCM + HMAC over record)
# ======================================================================

def encrypt_blob(plaintext: bytes, master_key: bytes, machine_fp: bytes) -> dict:
    """
    Encrypt a bytes blob with AES-256-GCM and record-level HMAC.
    Used to protect the entire vault JSON.
    """
    if len(master_key) != 32:
        raise ValueError("Master key must be 256 bits.")

    salt = secrets.token_bytes(16)           # per-encryption salt
    aes_key = derive_aes_key(master_key, salt, machine_fp)
    pepper = derive_pepper(master_key, machine_fp)
    cipher = AESGCM(aes_key)

    nonce = secrets.token_bytes(12)          # 96-bit nonce for GCM
    ciphertext = cipher.encrypt(nonce, plaintext, pepper)

    # Extra HMAC over (salt | nonce | ciphertext)
    hmac_input = salt + nonce + ciphertext
    record_hmac = hmac.new(pepper, hmac_input, hashlib.sha256).hexdigest()

    return {
        "ciphertext": ciphertext.hex(),
        "nonce": nonce.hex(),
        "salt": salt.hex(),
        "hmac": record_hmac,
    }


def decrypt_blob(enc_obj: dict, master_key: bytes, machine_fp: bytes) -> bytes:
    """
    Decrypt blob produced by encrypt_blob.
    Verifies HMAC before attempting AES-GCM decrypt.
    """
    ciphertext = bytes.fromhex(enc_obj["ciphertext"])
    nonce = bytes.fromhex(enc_obj["nonce"])
    salt = bytes.fromhex(enc_obj["salt"])
    record_hmac = enc_obj.get("hmac")

    aes_key = derive_aes_key(master_key, salt, machine_fp)
    pepper = derive_pepper(master_key, machine_fp)
    cipher = AESGCM(aes_key)

    hmac_input = salt + nonce + ciphertext
    expected_hmac = hmac.new(pepper, hmac_input, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(expected_hmac, record_hmac):
        raise ValueError(
            "Vault HMAC verification failed. File may be corrupted or tampered."
        )

    plaintext = cipher.decrypt(nonce, ciphertext, pepper)
    return plaintext


# ======================================================================
# HASHING / MULTI-LAYER HASHING (for future use)
# ======================================================================

def hashing_function(data: bytes, master_key: bytes, machine_fp: bytes,
                     h_algorithm: str = "HMAC-SHA256") -> str:
    """
    Multi-layer hashing using pepper + chosen algorithm.

    Supported:
      - "HMAC-SHA256"
      - "SHA3-512"
    """
    alg = h_algorithm.upper()
    pepper = derive_pepper(master_key, machine_fp)

    if alg == "HMAC-SHA256":
        return hmac.new(pepper, data, hashlib.sha256).hexdigest()

    if alg == "SHA3-512":
        first = hmac.new(pepper, data, hashlib.sha256).digest()
        return hashlib.sha3_512(first).hexdigest()

    raise ValueError("Unsupported hash algorithm.")


# ======================================================================
# PBKDF2 AUTO-TUNE (10s benchmark + multiplier recommendation)
# ======================================================================

def auto_tune_pbkdf(base_iterations: int, duration: float = 10.0,
                    test_iterations: int = 50_000):
    """
    Run PBKDF2 for ~duration seconds to estimate speed and calculate
    a recommended multiplier so that base_iterations * multiplier
    is ~0.8s per derivation.
    """
    print(f"[+] PBKDF2 auto-tune: running ~{duration:.0f}s benchmark...")
    password = b"benchmark-password"
    salt = b"benchmark-salt"
    calls = 0
    start = time.time()

    while True:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=test_iterations,
            backend=default_backend(),
        )
        kdf.derive(password)
        calls += 1
        elapsed = time.time() - start
        if elapsed >= duration:
            break

    total_iters = calls * test_iterations
    iters_per_sec = total_iters / elapsed
    time_per_iter = 1.0 / iters_per_sec
    base_time = time_per_iter * base_iterations

    print(f"[+] Benchmark complete. Approx iterations/sec: {iters_per_sec:,.0f}")
    print(f"[+] Estimated time for base {base_iterations:,} iterations: {base_time:.3f} seconds")

    target_time = 0.8  # target login time in seconds
    recommended_multiplier = target_time / base_time if base_time > 0 else 1.0

    # Bound it so the user doesn't accidentally set something insane
    recommended_multiplier = max(0.2, min(4.0, recommended_multiplier))
    return recommended_multiplier, base_time, iters_per_sec


# ======================================================================
# PASSWORD KDF + USER DATA KEY
# ======================================================================

def password_verifier(base_key: bytes) -> str:
    """
    Derive a non-reversible password verifier from the PBKDF2 base key.
    """
    return hashlib.sha256(b"pw-verifier|" + base_key).hexdigest()


def password_kdf_base(password: str, user_salt: bytes, master_key: bytes,
                      machine_fp: bytes, iterations: int) -> bytes:
    """
    PBKDF2-HMAC-SHA256 over (password, user_salt + machine_fp)
    → 32-byte base key (used as pw_hash and parent for user data key).
    """
    salt = user_salt + machine_fp
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend(),
    )
    return kdf.derive(password.encode("utf-8"))


def derive_user_data_key(username: str, base_key: bytes) -> bytes:
    """
    Derive a per-user AES key from the PBKDF2 base key via HKDF.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"user-data-key|" + username.encode("utf-8"),
        backend=default_backend(),
    )
    return hkdf.derive(base_key)


def get_pbkdf_iterations(vault: dict) -> int:
    cfg = vault.get("config", {})
    iters = cfg.get("pbkdf_iterations")
    if iters is None:
        return PBKDF2_BASE_ITERATIONS
    return int(iters)


# ======================================================================
# VAULT LOAD / SAVE
# ======================================================================

def load_vault(master_key: bytes, machine_fp: bytes) -> dict:
    """
    Load the encrypted vault, or create it with PBKDF tuning on first run.
    """
    if not os.path.exists(VAULT_FILE):
        print("[+] No existing vault found. Running first-time setup.")

        rec_mult, base_time, iters_per_sec = auto_tune_pbkdf(PBKDF2_BASE_ITERATIONS)
        rec_mult_rounded = round(rec_mult, 2)

        print(f"[+] Recommended PBKDF2 strength multiplier for this machine: {rec_mult_rounded}x")
        print("    (Higher = more secure but slower logins.)")
        user_in = input(f"Enter PBKDF2 multiplier (press Enter for {rec_mult_rounded}): ").strip()

        if user_in:
            try:
                mult = float(user_in)
                if mult <= 0:
                    raise ValueError()
            except ValueError:
                print("[-] Invalid multiplier. Using recommended value.")
                mult = rec_mult_rounded
        else:
            mult = rec_mult_rounded

        pbkdf_iterations = int(PBKDF2_BASE_ITERATIONS * mult)
        print(f"[+] Using PBKDF2 iterations: {pbkdf_iterations:,} (base {PBKDF2_BASE_ITERATIONS:,} x {mult})")

        vault = {
            "version": 2,
            "config": {
                "pbkdf_base": PBKDF2_BASE_ITERATIONS,
                "pbkdf_multiplier": mult,
                "pbkdf_iterations": pbkdf_iterations,
            },
            "users": {},
        }
        save_vault(vault, master_key, machine_fp)
        return vault

    with open(VAULT_FILE, "r", encoding="utf-8") as f:
        outer = json.load(f)

    plaintext = decrypt_blob(outer, master_key, machine_fp)
    vault = json.loads(plaintext.decode("utf-8"))

    if "version" not in vault or "users" not in vault:
        raise ValueError("Invalid vault structure.")

    if "config" not in vault:
        # Backward-compatible default
        vault["config"] = {
            "pbkdf_base": PBKDF2_BASE_ITERATIONS,
            "pbkdf_multiplier": 1.0,
            "pbkdf_iterations": PBKDF2_BASE_ITERATIONS,
        }

    return vault


def save_vault(vault: dict, master_key: bytes, machine_fp: bytes) -> None:
    """
    Encrypt and save the entire vault to disk.
    """
    plaintext = json.dumps(vault, ensure_ascii=False).encode("utf-8")
    outer = encrypt_blob(plaintext, master_key, machine_fp)

    with open(VAULT_FILE, "w", encoding="utf-8") as f:
        json.dump(outer, f, indent=2)


# ======================================================================
# USER MANAGEMENT
# ======================================================================

def create_user(vault: dict, username: str, password: str,
                master_key: bytes, machine_fp: bytes) -> None:
    if username in vault["users"]:
        raise ValueError("User already exists.")

    user_salt = secrets.token_bytes(16)
    iterations = get_pbkdf_iterations(vault)
    base_key = password_kdf_base(password, user_salt, master_key, machine_fp, iterations)
    pw_hash = base_key.hex()

    vault["users"][username] = {
        "salt": user_salt.hex(),
        "pw_hash": pw_hash,
        "entries": {},  # label -> { "nonce": "..", "ct": ".." }
    }


def verify_user(vault: dict, username: str, password: str,
                master_key: bytes, machine_fp: bytes):
    """
    Returns base_key on success, None on failure.
    """
    user = vault["users"].get(username)
    if not user:
        return None

    user_salt = bytes.fromhex(user["salt"])
    iterations = get_pbkdf_iterations(vault)
    base_key = password_kdf_base(password, user_salt, master_key, machine_fp, iterations)
    candidate_hash = base_key.hex()

    if not hmac.compare_digest(candidate_hash, user["pw_hash"]):
        return None

    return base_key


# ======================================================================
# VAULT ENTRIES (PER USER, PER-USER AES KEYS)
# ======================================================================

def add_secret(vault: dict, username: str, user_data_key: bytes,
               label: str, secret_value: str) -> None:
    """
    Store a secret under a label for a specific user.
    Encrypted with that user's AES key (derived from their password).
    """
    user = vault["users"].get(username)
    if not user:
        raise ValueError("User does not exist.")

    entries = user.setdefault("entries", {})
    cipher = AESGCM(user_data_key)
    nonce = secrets.token_bytes(12)
    ct = cipher.encrypt(nonce, secret_value.encode("utf-8"), None)

    entries[label] = {
        "nonce": nonce.hex(),
        "ct": ct.hex(),
    }


def list_secrets(vault: dict, username: str):
    user = vault["users"].get(username)
    if not user:
        return []
    return list(user.get("entries", {}).keys())


def get_secret(vault: dict, username: str, user_data_key: bytes, label: str) -> str:
    user = vault["users"].get(username)
    if not user:
        raise KeyError("User not found.")

    entry = user.get("entries", {}).get(label)
    if not entry:
        raise KeyError("Secret not found.")

    nonce = bytes.fromhex(entry["nonce"])
    ct = bytes.fromhex(entry["ct"])
    cipher = AESGCM(user_data_key)
    pt = cipher.decrypt(nonce, ct, None)
    return pt.decode("utf-8")


# ======================================================================
# MASTER KEY ROTATION
# ======================================================================

def rotate_master_key(vault: dict, current_master: bytes,
                      machine_fp: bytes) -> bytes:
    """
    Generate a new 256-bit master key, store it in keyring,
    and re-encrypt the vault with it.
    """
    print("[!] WARNING: Rotating master key.")
    print("    If something goes wrong during save, keep backups of your vault file.")
    confirm = input("Type 'ROTATE' to proceed: ").strip()

    if confirm != "ROTATE":
        print("[-] Master key rotation cancelled.")
        return current_master

    new_master = secrets.token_bytes(32)
    keyring.set_password(APP_NAME, MASTER_KEY_NAME, new_master.hex())
    save_vault(vault, new_master, machine_fp)
    print("[+] Master key rotated and vault re-encrypted.")
    return new_master


# ======================================================================
# CLI / MAIN LOOP
# ======================================================================

def main():
    master_key = get_or_create_master_key()
    machine_fp = get_machine_fingerprint()
    print("[+] Machine fingerprint:", machine_fp.hex())

    vault = load_vault(master_key, machine_fp)

    while True:
        print("\n=== Yuvi Secure Vault ===")
        print("1) Create user")
        print("2) Login")
        print("3) Rotate master key")
        print("4) Exit")
        choice = input("> ").strip()

        if choice == "1":
            username = input("New username: ").strip()
            password = input("New password: ").strip()
            confirm = input("Confirm password: ").strip()
            if password != confirm:
                print("[-] Passwords do not match.")
                continue
            try:
                create_user(vault, username, password, master_key, machine_fp)
                save_vault(vault, master_key, machine_fp)
                print("[+] User created.")
            except ValueError as e:
                print("Error:", e)

        elif choice == "2":
            username = input("Username: ").strip()
            password = input("Password: ").strip()

            base_key = verify_user(vault, username, password, master_key, machine_fp)
            if base_key is None:
                print("[-] Invalid username or password.")
                continue

            user_data_key = derive_user_data_key(username, base_key)
            print(f"[+] Logged in as {username}.")

            while True:
                print("\n--- User Menu ---")
                print("1) Add secret")
                print("2) List secrets")
                print("3) View secret")
                print("4) Logout")
                sub = input("> ").strip()

                if sub == "1":
                    label = input("Label for secret: ").strip()
                    value = input("Secret value: ").strip()
                    try:
                        add_secret(vault, username, user_data_key, label, value)
                        save_vault(vault, master_key, machine_fp)
                        print("[+] Secret stored.")
                    except ValueError as e:
                        print("Error:", e)

                elif sub == "2":
                    labels = list_secrets(vault, username)
                    if not labels:
                        print("No secrets stored.")
                    else:
                        print("Secrets:")
                        for lbl in labels:
                            print(" -", lbl)

                elif sub == "3":
                    label = input("Label to view: ").strip()
                    try:
                        value = get_secret(vault, username, user_data_key, label)
                        print(f"Secret[{label}] = {value}")
                    except KeyError as e:
                        print("Error:", e)

                elif sub == "4":
                    print("[+] Logged out.")
                    break

                else:
                    print("Invalid choice.")

        elif choice == "3":
            master_key = rotate_master_key(vault, master_key, machine_fp)

        elif choice == "4":
            break

        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()
