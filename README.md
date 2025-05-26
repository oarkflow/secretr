# Vault

Vault is a secure secret management tool implemented in Go. It provides encrypted storage, secure access, backup/restore features, and CLI/API interfaces to manage secrets.

## Features

- **Encryption & Security:**  
  Uses AES-GCM with a master key derived via Argon2id.  
  Device fingerprinting prevents vault access even if copied to another device.  
- **MasterKey Management:**  
  - Set up vault with a MasterKey.  
  - Change or rotate the MasterKey.
  - Reset functionality with emailed reset code if enabled.
- **Secret CRUD Operations:**  
  - Store (`set`) secrets with support for nested keys (using dot notation).
  - Retrieve (`get`) secrets.
  - Delete secrets.
  - List all secret keys.
- **Environment Integration:**  
  - Load and enrich environment variables from vault.
  - Set a single secret as an environment variable.
- **Backup & Restore:**  
  - Create backup copies via API or CLI.
  - Restore from backup files.
- **CLI & API:**  
  - Interactive CLI for managing secrets (`set`, `get`, `delete`, `copy`, `env`, `enrich`, `list`).
  - HTTP endpoints for key management, backup, and restore (see `/vault/backup` and `/vault/restore` endpoints).
- **Audit Logging:**  
  Writes audit logs with HMAC signatures to ensure tamper detection.
- **Additional Utilities:**  
  - Copy secret to clipboard.
  - Import/export vault data (JSON format).

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/oarkflow/vault.git
   ```
2. Build the project:
   ```bash
   cd vault
   go build ./cmd/main.go
   ```

## Usage

### Command-line Interface

- **Initialize and execute vault:**
  ```bash
  ./main
  ```
- **Interactive commands:**
  - `set <key>`: Set a secret. The tool will prompt for the value securely.
  - `get <key>`: Retrieve the value of a secret.
  - `delete <key>`: Remove a secret.
  - `copy <key>`: Copy the secret to the clipboard.
  - `env <key>`: Set the secret as an environment variable.
  - `load-env`: Load all environment variables from the vault.
  - `enrich`: Enrich the process's environment with all vault secrets.
  - `list`: Display all keys stored in vault.
  - `exit` / `quit`: Save and exit the CLI.

### API Endpoints

The vault also exposes HTTP endpoints:

- **List & Retrieve Keys:**
  - GET `/vault/` or `/vault/keys` to list all keys.
  - GET `/vault/<key>` to retrieve a specific secret.
- **Add/Update a Secret:**
  - POST/PUT `/vault/<key>` with the secret in the request body.
- **Delete a Secret:**
  - DELETE `/vault/<key>`
- **Clear Vault:**  
  - PATCH `/vault/clear` to remove all secrets.
- **Backup & Restore:**
  - POST `/vault/backup` to create a backup file.
  - POST `/vault/restore?path=<backup_path>` to restore the vault from a backup file.

## Configuration

- **Vault Directory:**  
  By default, the vault uses the `.vault` directory in your home folder. You can override this by setting the `VAULT_DIR` environment variable.
- **Reset Password:**  
  During the initial setup, you will have the option to enable reset password functionality.

## Examples

- **CLI Example:**
  ```bash
  vault> set my.secret
  Enter secret: *************
  vault> get my.secret
  *************
  vault> list
  my.secret
  ```
- **Programmatic Usage:**
  See `/examples/main.go` for an example that loads environment variables and retrieves secrets.

## Security Considerations

- Vault encrypts your secrets on disk. Ensure your master key is kept secure.
- Vault files are bound to the device they were created on using device fingerprinting.
- Even if a vault file is copied and the master key is known, it cannot be accessed from a different device.
- Regularly back up your vault using the provided backup commands.
- Audit logs are stored in the vault directory to track operations.
