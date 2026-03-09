# Key Recovery and Backup Guide

This guide explains what to back up, what can be recovered, and what cannot.

## What You Must Protect

- Private key files (`*_priv.bin` / `*_priv.pem`)
- Passwords used for password-based encryption
- Any recovery notes needed to identify which key/password was used

If private keys or passwords are lost, encrypted data may be permanently inaccessible.

## What to Back Up

Minimum recommended backup set:

1. `obsidianq.exe` and `ObsidianQ.Launcher.exe` release bundle (optional but useful)
2. Local keypair backups exported from **Settings**
3. Copies of older private keys used for historical vaults/files
4. A secure password manager entry for password-mode secrets

## Key Rotation and Older Data

Generating a new keypair does not invalidate older encrypted data.

- Older vaults/files may still require older private keys.
- Keep old private keys until you verify all important legacy data can be decrypted with newer material.

## If You Lose the Private Key

You can still decrypt only if one of these is true:

- You have another valid backup copy of that private key, or
- The data was encrypted in password mode and you still know the password.

Otherwise, recovery is not possible.

## If You Lose the Password

You can still decrypt only if that specific data was encrypted with key-based mode and you have the matching private key.

Otherwise, recovery is not possible.

## Best Practices

- Keep at least two backups in separate physical locations.
- Use encrypted external storage for backups.
- Test restore periodically (do not wait for an emergency).
- Label key backups with date and intended use.
- Do not store private keys in public cloud folders unencrypted.

## In-App Backup/Restore

Use **Settings**:

- `BACKUP LOCAL KEYPAIR`
- `RESTORE LOCAL KEYPAIR`

These actions are intended to reduce accidental key loss risk for local users.
