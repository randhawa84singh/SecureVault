# SecureVault

SecureVault is a single-script command-line tool for storing secrets in an encrypted vault. It manages configuration securely, supports optional machine binding, and keeps the interface minimal for non-interactive or TTY-driven workflows.

## Features
- **Obfuscated configuration** stored in `config.obf` protected by a master secret.
- **AES-GCM encryption** with HMAC integrity for vault data in `secure_vault.dat`.
- **Machine fingerprint binding** (optional) to tie vault keys to the current host.
- **Interactive and non-interactive flows** via CLI flags and environment variables.

## Requirements
- Python 3.10+
- [`cryptography`](https://pypi.org/project/cryptography/) package

Install dependencies with:

```bash
pip install -r requirements.txt  # if present
# or
pip install cryptography
```

## Configuration
SecureVault needs a master secret to protect the configuration values. Provide it through the `--master-secret` flag or the `MASTER_SECRET` environment variable. The configuration stores:
- Pepper value used in key derivation.
- PBKDF2 iteration count.
- Whether to bind vault keys to a machine fingerprint.

Create or refresh the configuration:

```bash
python main.py init-config --bind-machine --iterations 700000 --pepper <hex_pepper>
```
If you omit options, defaults are used and a random pepper is generated.

## Vault Usage
All vault commands share common flags:
- `--master-secret` — unlocks the obfuscated configuration (falls back to `MASTER_SECRET`).
- `--password` — vault password for non-interactive use (otherwise prompted).

### Store a secret
```bash
python main.py set <name> --value <secret_value>
```
If `--value` is omitted, you will be prompted.

### Retrieve a secret
```bash
python main.py get <name>
```
Prints the secret to stdout or exits with an error if missing.

### List secrets
```bash
python main.py list
```
Shows the stored secret names.

### Wipe the vault
```bash
python main.py wipe
```
Prompts for confirmation before deleting `secure_vault.dat`.

## Files
- `main.py` — SecureVault CLI implementation.
- `config.obf` — obfuscated configuration file written with mode `0600`.
- `secure_vault.dat` — encrypted vault data file written with mode `0600`.
- `ANALYSIS.md` — previous notes about configuration flow and risks.

## Tips
- Back up your master secret and vault password securely; losing them makes recovery impossible.
- When machine binding is enabled, the vault can only be unlocked on the machine that created it.
- Use environment variables in CI to avoid prompts (`MASTER_SECRET`, `PBKDF2_ITERS`, `AUTH_PEPPER`).
