🛰️ 1. Cryptography Agent

Purpose:
Responsible for all cryptographic operations. Prevents misuse of primitives and ensures every operation is compliant with modern cryptographic standards.

Responsibilities:

Provide safe wrappers for:

AES-256-GCM

ChaCha20-Poly1305

PBKDF2-HMAC-SHA256

Argon2id

HKDF-SHA256

HMAC-SHA256 / SHA3-512

Enforce:

High iteration counts

Random salts & pepper

Machine-binding (UUID/MAC/disk serial)

Constant-time comparison

Provide secure helper functions:

derive_admin_key()

derive_user_key()

derive_storage_key()

encrypt_blob()

decrypt_blob()

Reject insecure primitives:

MD5, SHA1, DES, ECB, RC4, static salts

Never performs:

Password verification

User management

File I/O

🕵️ 2. Authentication Agent

Purpose:
Handles identity, password workflows, and zero-knowledge verification.

Responsibilities:

Admin authentication flow

User authentication flow

Enforced lockout system (default: 5 attempts → 600 seconds)

Persist lockout metadata inside encrypted vault layer

PBKDF2 auto-tuning (10-second benchmark)

Duress-password support (optional)

Decoy-vault routing (optional)

Core features:

Does NOT see decrypted secrets

Only generates a derived login key via PBKDF2/Argon2id

Supports:

Admin password verification

User password verification

Per-user modern hashing

Secure salting + peppering

🔐 3. Vault Agent

Purpose:
Maintains secure vault data structures and handles multi-layer encryption.

Responsibilities:

Load/save vault (double-encrypted)

Validate vault integrity

Seal/unseal operations

Multi-layer envelope encryption:

Inner: admin-password AES-256-GCM

Outer: machine-bound AES-256-GCM + HMAC

Metadata management:

PBKDF2 iterations

Admin salts + vault salts

Lockout info

Tamper logs

Timestamping

Optional features:

Paranoid mode (read-only)

Self-destruct mode

Integrity HMAC over entire structure

Never performs:

Password checks

Secret encryption for individual users

🔑 4. User Secrets Agent

Purpose:
Manages per-user encrypted secrets using per-user derived AES keys.

Responsibilities:

Add secret

List secrets

Retrieve secret

Encrypt using user_key (HKDF from PBKDF base key)

Enforce:

Nonce uniqueness

Secret data validation

No plaintext leaks

Data stored:

{
  "nonce": "<hex>",
  "ct": "<hex>"
}


Never performs:

Admin operations

Vault-level encryption

PBKDF tuning

🧪 5. Validation & Compliance Agent

Purpose:
Runs continuous integrity tests and enforces standards across all agents.

Responsibilities:

Validate every cryptographic operation

Ensure derived keys match expected lengths

Detect misconfigured PBKDF2 iteration counts

Validate machine fingerprint consistency

Ensure nonce randomness & AEAD tag correctness

Unit-test vault:

User creation

Secret storage

Vault encryption

Vault rotation

Lockout behavior

Provides:

Red/green validation status

Warnings for insecure settings

Audit logs inside encrypted vault metadata

🔥 6. Key Rotation Agent

Purpose:
Coordinates full or partial rotation of master keys.

Responsibilities:

Rotate DPAPI/keyring master key

Re-encrypt entire vault with new outer key

Maintain compatibility with current admin password

Provide rollback recovery procedures

Validate fingerprints, salts, and HMACs before rotation

Security restrictions:

Requires admin unlock

Cannot run if vault is tampered

Logs all rotation attempts

📁 7. Backup & Migration Agent

Purpose:
Handles export/import workflows, supporting secure migration to new machines.

Responsibilities:

Export vault → password-only AES-256-GCM blob

Import → re-bind to machine fingerprint

Validate exported blobs before writing them

Allow user configuration for backup KDF strength

Supports:

Export PBKDF2=1,000,000 (recommended)

User-chosen iteration count

Upgrade/downgrade compatibility

🧱 8. Hardening Agent

Purpose:
Adds extra layers of defense and anti-tamper controls.

Features:

Integrity HMAC over entire vault structure

Timestamp-based tamper detection

Code path seal verification

Evaluates attacker models:

GPU brute-force

Memory scraping

Python code patching

Disk cloning

VM migration

Adds mitigation flags for:

Anti-debug

Anti-tamper

Metadata obfuscation

🗄️ 9. Audit Agent

Purpose:
Maintains logs of all sensitive events. Logs are encrypted inside the vault.

Logs:

Admin unlock attempts

Lockout triggers

Vault saves

Master key rotations

User creations

Tamper warnings

Guarantees:

Logs cannot be read without admin password

Logs cannot be modified without altering integrity hash

🧩 10. Orchestration / Kernel Agent

Purpose:
Coordinates all other agents safely.

Responsibilities:

Strict routing of all API calls

Enforces agent boundaries

Ensures cryptographic dependencies feed correct components

Executes vault load/save state machine:

Admin unlock

Decrypt outer

Validate integrity

Decrypt inner

Load config

Serve user or admin menu

Re-encrypt on save

Verifies correct order of operations

Rejects mis-ordered or illegal calls

🧩 Summary Diagram
             ┌─────────────────────┐
             │  Authentication      │
             └──────────┬──────────┘
                        │ admin_pw
                        ▼
              ┌────────────────────┐
              │ Inner Encryption   │
              └──────────┬─────────┘
                         │ plaintext vault
             ┌───────────▼────────────┐
             │  Vault Agent (meta)     │
             └───────────┬────────────┘
                         │ inner_bytes
            ┌────────────▼──────────────┐
            │ Outer Encryption (machine) │
            └────────────┬──────────────┘
                         │ ciphertext blob
                     yuvi_vault.dat
