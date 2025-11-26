#!/usr/bin/env python3
"""
secure_portal_final_nohardcode.py

Final single-file secure local portal, with no fixed secrets in the .py file.
Features:
 - Runtime-obfuscated local config (config.obf) protected by a master secret (prompt or env MASTER_SECRET)
 - Multi-stage password hashing pipeline:
       SHA3-512 -> BLAKE2b -> PBKDF2-HMAC-SHA256 -> SHA-512
   final HMAC wrap keyed by username-derived key
 - Strong PBKDF2 iterations configurable via obfuscated config (no hardcoded PBKDF2_ITERATIONS)
 - First-run wizard (creates admin), one-time recovery token printed (store offline)
 - Integrity HMAC for users.json (users.json.hmac) and recovery.hmac requires token if tampered
 - Per-user encrypted notebook (AES-GCM via cryptography) — script requires `cryptography` for encryption
 - Per-user JSON metadata (userdata/<user>.json) for keys/logbook metadata
 - No fixed sensitive variables in the script; everything secret comes from config.obf (protected by master secret)
 - No USB backup code and no plaintext backup file written

Usage:
  python secure_portal_final_nohardcode.py

Requirements:
 - Python 3.8+
 - cryptography for notebook encryption (optional but strongly recommended)
"""

import os, sys, json, secrets, getpass, time, hmac, hashlib, base64
from pathlib import Path
from datetime import datetime

# -------------------
# Config-obfuscation helpers (no secrets in .py)
# -------------------
CONFIG_FILE = Path("config.obf")

def _derive_key(master_secret: str) -> bytes:
    return hashlib.sha256(master_secret.encode()).digest()

def obfuscate_string(plain: str, master_secret: str, offset: int = 13) -> str:
    key = _derive_key(master_secret)
    b = plain.encode()
    out = bytearray(len(b))
    for i, val in enumerate(b):
        k = key[i % len(key)]
        out[i] = ((val ^ k) + offset) & 0xFF
    return out.hex()

def deobfuscate_string(hexstr: str, master_secret: str, offset: int = 13) -> str:
    key = _derive_key(master_secret)
    raw = bytes.fromhex(hexstr)
    out = bytearray(len(raw))
    for i, val in enumerate(raw):
        k = key[i % len(key)]
        out[i] = ((val - offset) & 0xFF) ^ k
    return out.decode()

def load_config(master_secret: str):
    if not CONFIG_FILE.exists():
        return None
    raw = CONFIG_FILE.read_text(encoding="utf8")
    try:
        data = json.loads(raw)
        offset = int(data.get("offset", 13))
        conf = {}
        conf['PEPPER'] = deobfuscate_string(data['pepper'], master_secret, offset=offset)
        conf['PBKDF2_ITERATIONS'] = int(deobfuscate_string(data['iters'], master_secret, offset=offset))
        conf['USE_MACHINE_BINDING'] = bool(int(deobfuscate_string(data['bind'], master_secret, offset=offset)))
        return conf
    except Exception as e:
        raise RuntimeError("Failed to load config; wrong master secret or corrupted config") from e

def save_config(pepper: str, pbkdf2_iters: int, use_machine_binding: bool, master_secret: str, offset: int = 13):
    data = {
        "pepper": obfuscate_string(pepper, master_secret, offset=offset),
        "iters": obfuscate_string(str(int(pbkdf2_iters)), master_secret, offset=offset),
        "bind": obfuscate_string("1" if use_machine_binding else "0", master_secret, offset=offset),
        "offset": offset
    }
    tmp = CONFIG_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf8")
    os.replace(tmp, CONFIG_FILE)
    try:
        os.chmod(CONFIG_FILE, 0o600)
    except Exception:
        pass

def prompt_for_master_secret():
    env = os.environ.get("MASTER_SECRET")
    if env:
        return env
    ms = getpass.getpass("Enter master secret (protects local config file): ").strip()
    if not ms:
        raise RuntimeError("Master secret required. Exiting.")
    return ms

def first_run_config_wizard(master_secret: str, recommended_iters: int = None):
    print("\n--- First run: create local obfuscated config (config.obf) ---")
    pepper = os.environ.get("AUTH_PEPPER") or input("Enter AUTH_PEPPER (long random hex) or leave blank to auto-generate: ").strip()
    if not pepper:
        pepper = secrets.token_hex(32)
        print("\nGenerated AUTH_PEPPER (set it permanently if you want portability):")
        if os.name == "nt":
            print(f"  setx AUTH_PEPPER {pepper}")
        else:
            print(f"  export AUTH_PEPPER={pepper}")
    if recommended_iters:
        print(f"Suggested PBKDF2 iterations for your machine: {recommended_iters:,d}")
    while True:
        iters_in = os.environ.get("PBKDF2_ITERS") or input("Enter PBKDF2 iterations (e.g. 3500000): ").strip()
        try:
            iters_val = int(iters_in)
            if iters_val <= 0:
                raise ValueError
            break
        except Exception:
            print("Invalid integer. Try again.")
    bind_in = input("Enable machine-binding? (y/N): ").strip().lower()
    bind_val = bool(bind_in == "y")
    save_config(pepper, iters_val, bind_val, master_secret)
    print("Local obfuscated config saved to config.obf. Master secret is required to read it later.")
    return {"PEPPER": pepper, "PBKDF2_ITERATIONS": iters_val, "USE_MACHINE_BINDING": bind_val}

def get_runtime_config(recommended_iters: int = None):
    master_secret = prompt_for_master_secret()
    conf = load_config(master_secret)
    if conf is not None:
        return conf, master_secret
    conf = first_run_config_wizard(master_secret, recommended_iters=recommended_iters)
    return conf, master_secret

# -------------------
# End config-obfuscation
# -------------------

# ---- After we obtain runtime config, we set these globals ----
conf, MASTER_SECRET = None, None
try:
    # recommended_iters can be suggested if you want; use None for no suggestion
    conf, MASTER_SECRET = get_runtime_config(recommended_iters=None)
except Exception as e:
    print("Error obtaining runtime config:", e)
    sys.exit(1)

PEPPER = conf['PEPPER']
PBKDF2_ITERATIONS = int(conf['PBKDF2_ITERATIONS'])
USE_MACHINE_BINDING = bool(conf['USE_MACHINE_BINDING'])

# ---- File layout ----
USER_FILE = Path("users.json")
HMAC_USERS = Path("users.json.hmac")
RECOVERY_HMAC = Path("recovery.hmac")
USERDATA_DIR = Path("userdata")
USERDATA_DIR.mkdir(exist_ok=True)

# ---- Cryptography availability for notebook encryption ----
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    CRYPTO_AVAILABLE = True
except Exception:
    CRYPTO_AVAILABLE = False

# ---- Safe file write helpers ----
def safe_write_json(path: Path, data):
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf8") as f:
        json.dump(data, f, indent=2)
        f.flush(); os.fsync(f.fileno())
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass

def safe_write_bytes(path: Path, b: bytes):
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "wb") as f:
        f.write(b)
        f.flush(); os.fsync(f.fileno())
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass

# ---- Machine info and username-derived key ----
def _machine_info():
    import platform, socket
    try:
        return f"{platform.system()}|{socket.gethostname()}|{platform.processor()}"
    except Exception:
        return "unknown-machine"

def _username_key(username: str) -> bytes:
    base = username + (PEPPER or "")
    if USE_MACHINE_BINDING:
        base += "|" + _machine_info()
    return hashlib.sha3_256(base.encode()).digest()

# ---- Multi-stage hash pipeline & verify ----
def _hash_stage(algo, data: bytes, salt: bytes | None = None, iters: int | None = None) -> bytes:
    if algo == "sha3_512":
        return hashlib.sha3_512(data).digest()
    if algo == "blake2b":
        return hashlib.blake2b(data, salt=salt).digest()
    if algo == "sha512":
        return hashlib.sha512(data).digest()
    if algo == "pbkdf2_sha256":
        return hashlib.pbkdf2_hmac("sha256", data, salt, iters or PBKDF2_ITERATIONS)
    raise ValueError("Unknown algo: " + str(algo))

HASH_CHAIN = ["sha3_512", "blake2b", "pbkdf2_sha256", "sha512"]

def hash_password(password: str, username: str = "", salt: bytes | None = None) -> str:
    if not salt:
        salt = secrets.token_bytes(16)
    data = (PEPPER + password).encode()
    for algo in HASH_CHAIN:
        if algo.startswith("pbkdf2"):
            data = _hash_stage(algo, data, salt=salt, iters=PBKDF2_ITERATIONS)
        else:
            data = _hash_stage(algo, data, salt=salt)
    ukey = _username_key(username)
    final = hmac.new(ukey, data, hashlib.sha512).digest()
    return f"multiuser${PBKDF2_ITERATIONS}${salt.hex()}${final.hex()}"

def verify_password(stored_hash: str, password: str, username: str = "") -> bool:
    try:
        _, iters_str, salt_hex, stored_hex = stored_hash.split("$")
        salt = bytes.fromhex(salt_hex)
        iters = int(iters_str)
        data = (PEPPER + password).encode()
        for algo in HASH_CHAIN:
            if algo.startswith("pbkdf2"):
                data = _hash_stage(algo, data, salt=salt, iters=iters)
            else:
                data = _hash_stage(algo, data, salt=salt)
        ukey = _username_key(username)
        final = hmac.new(ukey, data, hashlib.sha512).digest()
        return hmac.compare_digest(final.hex(), stored_hex)
    except Exception:
        return False

# ---- Notebook encryption helpers (AES-GCM) ----
def derive_notebook_key(username: str) -> bytes:
    if not PEPPER:
        raise RuntimeError("PEPPER (AUTH_PEPPER) must be set for notebook encryption.")
    salt = hashlib.sha256((username + "notebook-salt").encode()).digest()[:16]
    key = hashlib.pbkdf2_hmac("sha256", (PEPPER + username).encode(), salt, 200_000, dklen=32)
    return key

def encrypt_notebook_blob(username: str, plaintext_bytes: bytes) -> bytes:
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("cryptography package missing. Install with: pip install cryptography")
    key = derive_notebook_key(username)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ct = aesgcm.encrypt(nonce, plaintext_bytes, None)
    return base64.b64encode(nonce + ct)

def decrypt_notebook_blob(username: str, b64_blob: bytes) -> bytes:
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("cryptography package missing. Install with: pip install cryptography")
    raw = base64.b64decode(b64_blob)
    nonce = raw[:12]; ct = raw[12:]
    key = derive_notebook_key(username)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)

# ---- Integrity & recovery (no plaintext backups) ----
def _hmac_bytes(key: bytes, data: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()

def create_recovery_token_and_sign(users_data: dict):
    key = (PEPPER or "").encode()
    token = secrets.token_urlsafe(24)
    token_hmac = _hmac_bytes(key, token.encode())
    RECOVERY_HMAC.write_text(token_hmac, encoding="utf8")
    users_bytes = json.dumps(users_data, sort_keys=True).encode()
    users_hmac = _hmac_bytes(key, users_bytes)
    HMAC_USERS.write_text(users_hmac, encoding="utf8")
    # show token once
    print("\n=== IMPORTANT: Recovery token (store offline) ===")
    print("This token is shown once. Save it to a secure offline place (USB or printed).")
    print("You will need it to recover if users.json is deleted or tampered with.\n")
    print(token)
    print("\nSave this token now. Script will continue.\n")
    return token

def verify_users_integrity_or_require_token():
    key = (PEPPER or "").encode()
    if not RECOVERY_HMAC.exists():
        return None
    stored_recovery_hmac = RECOVERY_HMAC.read_text(encoding="utf8").strip()
    if not USER_FILE.exists() or not HMAC_USERS.exists():
        print("⚠️ users.json or integrity metadata missing. Recovery token required to proceed.")
        return _ask_and_verify_recovery_token(key, stored_recovery_hmac)
    try:
        users_bytes = USER_FILE.read_bytes()
        users_json = json.loads(users_bytes)
        normalized = json.dumps(users_json, sort_keys=True).encode()
        expected = _hmac_bytes(key, normalized)
        stored_users_hmac = HMAC_USERS.read_text(encoding="utf8").strip()
        if not hmac.compare_digest(expected, stored_users_hmac):
            print("⚠️ users.json HMAC mismatch — file may have been tampered. Recovery token required.")
            return _ask_and_verify_recovery_token(key, stored_recovery_hmac)
        return True
    except Exception as e:
        print("Error verifying integrity:", e)
        return False

def _ask_and_verify_recovery_token(key: bytes, stored_recovery_hmac: str) -> bool:
    token = getpass.getpass("Enter offline recovery token (hidden): ").strip()
    if not token:
        print("No token entered. Aborting.")
        return False
    token_hmac = _hmac_bytes(key, token.encode())
    if hmac.compare_digest(token_hmac, stored_recovery_hmac):
        print("Recovery token accepted.")
        confirm = input("Confirm you want to reinitialize users.json (type 'I UNDERSTAND' to proceed): ").strip()
        if confirm == "I UNDERSTAND":
            return True
        print("Aborted by user.")
        return False
    else:
        print("Invalid recovery token.")
        return False

# ---- User data helpers ----
def load_users():
    if not USER_FILE.exists():
        return {}
    return json.loads(USER_FILE.read_text(encoding="utf8"))

def save_users(users_dict):
    safe_write_json(USER_FILE, users_dict)
    if RECOVERY_HMAC.exists():
        key = (PEPPER or "").encode()
        normalized = json.dumps(users_dict, sort_keys=True).encode()
        HMAC_USERS.write_text(_hmac_bytes(key, normalized), encoding="utf8")

def get_userdata_path(username: str) -> Path:
    return USERDATA_DIR / f"{username}.json"

def get_notebook_path(username: str) -> Path:
    return USERDATA_DIR / f"{username}.nb"

def load_userdata(username: str) -> dict:
    p = get_userdata_path(username)
    if not p.exists():
        d = {"logbook_meta": [], "keys": []}
        safe_write_json(p, d)
        return d
    return json.loads(p.read_text(encoding="utf8"))

def save_userdata(username: str, data: dict):
    safe_write_json(get_userdata_path(username), data)

def load_notebook(username: str) -> list:
    nbp = get_notebook_path(username)
    if not nbp.exists():
        return []
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("cryptography missing; cannot decrypt notebook.")
    blob = nbp.read_bytes()
    plaintext = decrypt_notebook_blob(username, blob)
    return json.loads(plaintext.decode())

def save_notebook(username: str, entries: list):
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("cryptography missing; cannot encrypt notebook.")
    plaintext = json.dumps(entries, indent=2).encode()
    blob = encrypt_notebook_blob(username, plaintext)
    safe_write_bytes(get_notebook_path(username), blob)

# ---- First-run wizard & setup ----
def first_run_wizard():
    print("\n=== First-Run Setup Wizard ===\n")
    global PEPPER
    if not PEPPER:
        pepper_val = secrets.token_hex(32)
        print("Generated AUTH_PEPPER (set it permanently if you want portability):")
        if os.name == "nt":
            print(f"  setx AUTH_PEPPER {pepper_val}")
        else:
            print(f"  export AUTH_PEPPER={pepper_val}")
        os.environ["AUTH_PEPPER"] = pepper_val
        PEPPER = pepper_val

    while True:
        admin_user = input("Create admin username: ").strip()
        if not admin_user:
            print("Username cannot be empty.")
            continue
        pw1 = getpass.getpass("Create password: ")
        pw2 = getpass.getpass("Confirm password: ")
        if pw1 != pw2:
            print("Passwords do not match.")
            continue
        users = {admin_user: hash_password(pw1, admin_user)}
        save_users(users)
        create_recovery_token_and_sign(users)
        print("\nAdmin user created and signed. You can now log in.")
        save_userdata(admin_user, {"logbook_meta": [], "keys": []})
        try:
            if CRYPTO_AVAILABLE:
                save_notebook(admin_user, [])
            else:
                print("Note: cryptography not installed. Install `pip install cryptography` to enable notebook encryption.")
        except Exception:
            pass
        return

# ---- Dashboard UI ----
def user_dashboard(username: str):
    userdata = load_userdata(username)
    try:
        entries = load_notebook(username)
    except RuntimeError as e:
        entries = []
        print("Notebook unavailable:", e)
    while True:
        print(f"\n=== Dashboard: {username} ===")
        print("1) View notebook entries")
        print("2) Add notebook entry")
        print("3) View security keys")
        print("4) Add security key")
        print("5) Show encrypted notebook path")
        print("6) Logout")
        choice = input("Choice: ").strip()
        if choice == "1":
            if not entries:
                print("Notebook is empty.")
            else:
                for i, e in enumerate(entries, 1):
                    print(f"[{i}] {e['time']} - {e['title']}\n    {e['text']}")
        elif choice == "2":
            title = input("Entry title: ").strip()
            text = input("Entry text: ").strip()
            entry = {"time": datetime.now().isoformat(), "title": title, "text": text}
            entries.append(entry)
            try:
                save_notebook(username, entries)
                print("Entry saved and encrypted.")
            except RuntimeError as e:
                print("Failed to save encrypted notebook:", e)
                userdata.setdefault("logbook_meta", []).append({"time": entry["time"], "title": title})
                save_userdata(username, userdata)
                print("Saved metadata only.")
        elif choice == "3":
            keys = userdata.get("keys", [])
            if not keys:
                print("No security keys saved.")
            else:
                for i, k in enumerate(keys, 1):
                    print(f"{i}. {k}")
        elif choice == "4":
            k = input("Enter security key/token to save: ").strip()
            userdata.setdefault("keys", []).append(k)
            save_userdata(username, userdata)
            print("Key saved in userdata (plaintext file under userdata/). Consider storing sensitive keys elsewhere.")
        elif choice == "5":
            nbp = get_notebook_path(username)
            if nbp.exists():
                print(f"Encrypted notebook blob at: {nbp.resolve()}")
            else:
                print("No encrypted notebook found.")
        elif choice == "6":
            print("Logging out.")
            break
        else:
            print("Invalid choice.")

# ---- Main flow ----
def main():
    state = verify_users_integrity_or_require_token()
    if state is False:
        print("Integrity verification failed. Exiting.")
        return
    if state is None:
        print("No prior installation detected. Running first-run wizard.")
        first_run_wizard()

    users = load_users()
    action = input("login or signup? ").strip().lower()
    username = input("username: ").strip()
    password = getpass.getpass("password: ")

    if action == "signup":
        if username in users:
            print("User exists.")
            return
        users[username] = hash_password(password, username)
        save_users(users)
        print("Account created. IMPORTANT: you should create a new recovery token and HMAC manually if needed.")
        return

    if action == "login":
        if username in users and verify_password(users[username], password, username):
            print(f"Welcome, {username}!")
            save_userdata(username, load_userdata(username))
            user_dashboard(username)
        else:
            print("Invalid username or password.")
        return

    print("Type login or signup.")

if __name__ == "__main__":
    if not CRYPTO_AVAILABLE:
        print("NOTE: cryptography not installed. Notebook encryption disabled.")
        print("Install with: pip install cryptography")
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted. Exiting.")
