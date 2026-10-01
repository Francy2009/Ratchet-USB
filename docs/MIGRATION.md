# Vault migration

Legacy vaults cannot be used by ordinary commands. Migration is explicit:

1. Run `ratchet-usb migrate --usb-path <drive>` and enter the legacy password.
2. The complete legacy store is authenticated and parsed. A v3 vault is written
   as `vault.bin.v3-prepared`, reopened, decrypted and checked for matching
   identity and an advanced generation.
3. While that prepared file exists, ordinary CLI/TUI use is blocked.
4. Run `ratchet-usb migrate --commit --usb-path <drive>` and enter the password
   again. The prepared bytes are verified again and atomically replace
   `vault.bin`; the directory is then synced.

Contacts and aliases remain. Existing sessions are marked legacy read-only and
cannot send. Importing the same contact's dual-signed PQ card clears the legacy
session and the old verified flag, so a fresh out-of-band check is required.

Commit enrolls a host rollback anchor when a supported service is available.
The old directory entry is removed atomically, but physical erasure of old
pages on flash media cannot be guaranteed.
