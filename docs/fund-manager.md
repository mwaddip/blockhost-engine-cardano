# Fund Manager

Integrated into the monitor polling loop. Automates batch collection of mature subscription UTXOs and distribution of collected funds.

There is no gas check cycle. Cardano fees are deterministic — no gas market, no gas top-up logic needed between fund cycles.

## Fund Cycle (every 24h, configurable)

1. **Batch collect** — Consume all mature subscription UTXOs from the validator address in one transaction (or batched transactions if the UTXO count is large). Collected ADA flows to the hot wallet.
2. **Hot wallet ADA** — Server sends ADA to hot wallet if below `hot_wallet_gas_lovelace` threshold.
3. **Server stablecoin buffer** — Hot wallet sends stablecoin tokens to server if below `server_stablecoin_buffer_lovelace` threshold.
4. **Revenue shares** — If enabled in `revenue-share.json`, distribute configured basis points to dev/broker.
5. **Remainder to admin** — Send all remaining hot wallet ADA and token balances to admin.

The fund cycle is skipped (deferred) if a provisioner `create` command is detected running (`pgrep -f <create_cmd>`), to avoid ADA balance race conditions during VM provisioning.

## Batch Collection

Collection is UTXO-native on Cardano. The fund manager queries Blockfrost for all UTXOs at the subscription validator address that carry a beacon token under the beacon policy, filters for mature subscriptions (`datum.expiry < now`), and builds a transaction that:

- Spends all selected subscription UTXOs with the `ServiceCollect` redeemer
- Burns the beacon token for each consumed UTXO (satisfies the beacon minting policy's `CloseSubscription` check)
- Sends the collected ADA to the hot wallet

Transaction building requires MeshJS integration (partially implemented in `src/fund-manager/withdrawal.ts`).

## Distribution

All monetary values are in **lovelace** (1 ADA = 1,000,000 lovelace). Token amounts are in their respective base units.

Implemented in `src/fund-manager/distribution.ts`:
- `topUpHotWalletGas(book, config, client)` — top up hot wallet ADA from server
- `topUpServerStablecoinBuffer(book, config, client)` — top up server stablecoin from hot wallet
- `distributeRevenueShares(book, revenueConfig, client)` — send shares to dev/broker by basis points
- `sendRemainderToAdmin(book, client)` — sweep remaining hot wallet balances to admin

## Hot Wallet

Auto-generated on first fund cycle if not in the addressbook. The root agent's `generate-wallet` action creates the wallet:
- Generates a 24-word BIP39 mnemonic via `keygen.ts`
- Saves the mnemonic to `/etc/blockhost/hot.key` (chmod 600)
- Adds the `hot` entry to `addressbook.json`

Acts as an intermediary: collected subscription funds flow through the hot wallet before going to final recipients.

## Configuration

In `/etc/blockhost/blockhost.yaml` under the `fund_manager:` key:

| Setting | Default | Description |
|---------|---------|-------------|
| `fund_cycle_interval_hours` | 24 | Hours between fund cycles |
| `min_withdrawal_lovelace` | 50,000,000 | Minimum ADA (in lovelace) at validator before collection triggers |
| `gas_low_threshold_lovelace` | 5,000,000 | Server ADA balance (lovelace) that triggers a warning |
| `hot_wallet_gas_lovelace` | 5,000,000 | Target ADA balance (lovelace) for hot wallet |
| `server_stablecoin_buffer_lovelace` | 5,000,000 | Target stablecoin balance (token base units) for server wallet |
