# Reconciler

Runs every hour as part of the monitor polling loop. Performs three passes over active/suspended VMs in `vms.json`:

1. **NFT ownership** — match local `owner_wallet` to the on-chain holder; propagate transfers to the VM's GECOS field.
2. **NFT minting check** — warn when the local DB believes a token was minted but the chain disagrees.
3. **Network config sync** — retry `blockhost-network-hook push-vm-config` for any VM whose initial post-mint push didn't confirm.

## NFT Ownership Scan

For every active or suspended VM that has a minted NFT, the reconciler:

1. Queries Blockfrost for the current holder of the CIP-68 `(222)` user token (`000de140` prefix)
2. Compares the on-chain holder against the locally stored `owner_wallet`
3. On transfer detection: updates the VM record and propagates the change to the VM's GECOS field

The reconciler queries by policy ID + token ID via `findNftHolder()` (`src/nft/reference.ts`), which uses `client.assetsAddresses()` to find the current address holding the user token.

## Ownership Transfer Detection

When the on-chain holder differs from `owner_wallet`:

1. Updates `wallet_address` and sets `gecos_synced = false` in the Python `vm_db`
2. Calls the provisioner's `update-gecos` command to update the VM's GECOS field (`wallet=<addr>,nft=<id>`)
3. On success: sets `gecos_synced = true`

If `update-gecos` fails (VM stopped, QEMU guest agent unresponsive), `gecos_synced` stays `false`. On the next reconcile cycle, the ownership comparison matches (local was already updated), but the persisted `gecos_synced === false` flag triggers a retry of the GECOS write.

This is the sole mechanism by which VMs learn about NFT ownership changes after provisioning. The PAM module authenticates against the VM's GECOS field, not the blockchain directly.

### Provisioner Command

```
getCommand("update-gecos") <vm-name> <wallet-address> --nft-id <token_id>
```

Exit 0 = GECOS updated. Exit 1 = failed (retried next cycle).

## NFT Minting Check

For VMs where `nft_minted` is `false`, the reconciler checks whether the token is already on-chain (e.g. after a monitor restart or a minting race). If the token exists on-chain, it marks `nft_minted = true` locally and updates GECOS if needed.

If the token is not found on-chain and `nft_minted` is `false`, a warning is logged for operator attention — this indicates a minting failure in the pipeline.

## Network Config Sync

For every active/suspended VM whose `network_config_synced` field is not `true`, the reconciler runs:

```
blockhost-network-hook push-vm-config <vm-name>
```

The dispatcher resolves the VM's `network_mode` from `vm-db` and forwards to the active plugin. On exit 0 the reconciler writes `network_config_synced = true` via `blockhost-vmdb update-fields`; on failure the flag is left as-is and the next cycle retries.

The handler also writes the flag at provision time (after the post-mint push), so VMs whose first push succeeded are skipped on every subsequent cycle. Plugins implement `push-vm-config` as idempotent (no-op for `broker`/`manual`/`none`), so unconditional retries are safe.

## Concurrency Guard

A `reconcileInProgress` flag prevents concurrent runs. If the reconciler is triggered while a previous run is still in progress, the new invocation returns immediately without doing any work.

## Retry Logic

Failed GECOS updates are retried every reconcile cycle (every hour) until they succeed. The `gecos_synced` flag in `vms.json` persists across monitor restarts. Failed `push-vm-config` calls are retried under the same cadence via `network_config_synced`.

Blockfrost query errors for individual VMs are logged and counted but do not abort the rest of the reconcile pass.
