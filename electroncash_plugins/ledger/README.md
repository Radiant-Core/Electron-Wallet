# Ledger Hardware Wallet Plugin for Electron Radiant

Provides Ledger hardware wallet support for Electron Radiant.

---

## Status

The plugin supports:
- ✅ Connecting a Ledger device to derive xpub and generate a watch-only wallet
- ✅ Displaying receive addresses on the device
- ✅ **Signing transactions** via PSBTv2 — requires the custom **Radiant Ledger app** (see below)
- ❌ Signing with stock Bitcoin or Bitcoin Cash app (firmware incompatibility — see below)

### Signing Flow (app-radiant)
Signing uses **PSBTv2** with `SIGHASH_FORKID|SIGHASH_ALL` (0x41) per input.
The policy is `pkh(@0/**)` at `m/44'/0'/0'` (standard Radiant P2PKH path).

---

## Technical Root Cause

### Radiant's Modified BIP143 Preimage

Radiant uses a **modified BIP143** sighash preimage with an extra field not present in
any standard Bitcoin or BCH app:

| Field | Standard BIP143 (BCH) | Radiant BIP143 |
|---|---|---|
| nVersion | ✅ | ✅ |
| hashPrevouts | ✅ | ✅ |
| hashSequence | ✅ | ✅ |
| outpoint | ✅ | ✅ |
| scriptCode | ✅ | ✅ |
| value | ✅ | ✅ |
| nSequence | ✅ | ✅ |
| **hashOutputHashes** | ❌ absent | ✅ **extra field** |
| hashOutputs | ✅ | ✅ |
| nLocktime | ✅ | ✅ |
| nHashType | ✅ | ✅ |

`hashOutputHashes = SHA256d(concat of [amount(8) + SHA256d(script)(32) + zeros(36)] for each output)`

### Why No Existing App Works

The Ledger secure element computes the BIP143 sighash preimage **internally in firmware**.
There is no APDU to inject extra fields or override the preimage structure. The BCH app's
`startUntrustedTransaction` with `cashAddr=True` (p2=0x03) is the closest match for
SIGHASH_FORKID, but it generates the standard BCH preimage (without `hashOutputHashes`),
producing a different 32-byte digest than Radiant expects. The resulting signature is
rejected with `mandatory-script-verify-flag-failed`.

### Hash Algorithm

- **Transaction sighash**: SHA256d (double SHA256) — same as Bitcoin/BCH ✅  
- **Block headers only**: SHA512/256d — NOT used for tx signatures

---

## Supported Devices (Watch-Only)

| Device | Recommended App | Purpose |
|---|---|---|
| Nano S (legacy) | Bitcoin Cash | xpub derivation + address display |
| Nano X | Bitcoin Cash | xpub derivation + address display |
| Nano S Plus | Bitcoin Cash | xpub derivation + address display |
| Stax | Bitcoin Cash | xpub derivation + address display |
| Flex | Bitcoin Cash | xpub derivation + address display |

---

## Setup Instructions (Watch-Only Wallet)

1. Connect your Ledger via USB and enter your PIN.
2. Open the **Bitcoin Cash** app on the device.
3. Disable **"Browser support"** in app settings (Nano S / Blue only).
4. Close Ledger Live and any other app using the device.
5. In Electron Radiant: **New Wallet → Hardware Device → Ledger → derivation `m/44'/0'/0'`**.
6. The wallet opens in watch-only mode. Addresses can be verified on-device.

---

## Custom Radiant Ledger App

The custom **app-radiant** firmware is a fork of
[`app-bitcoin-new`](https://github.com/LedgerHQ/app-bitcoin-new) with the following change:

- `hashOutputHashes = SHA256d(∑ [amount(8) + SHA256d(script)(32) + zeros(36)])` is inserted
  before `hashOutputs` in `compute_sighash_segwitv0()` when `SIGHASH_FORKID` (0x41) is set

Source: `/Users/main/Downloads/app-radiant`

To load onto a device (requires Ledger developer mode):
```
make COIN=radiant TARGET_NAME=TARGET_NANOSP load
```

> Once submitted to Ledger for signing, users can install it from the Ledger app store.

---

## Python Dependencies

```
pip install ledger_bitcoin[hid]   # required for device connection and xpub derivation
```

---

## Official Resources

- [Ledger Developer Portal](https://developers.ledger.com)
- [ledger-bitcoin Python library](https://pypi.org/project/ledger-bitcoin/)
- [app-bitcoin-new source](https://github.com/LedgerHQ/app-bitcoin-new)
- [Radiant transaction.py serialize_preimage()](../../../electroncash/transaction.py)

---

## Troubleshooting

- **Device not connecting**: Ensure the Radiant app is open on device and Browser support is disabled (Nano S/Blue).
- **Signing fails**: Ensure the custom **app-radiant** is installed. Signing is not supported with the stock Bitcoin or Bitcoin Cash app.
- **Device not recognised**: Ensure firmware is up to date via Ledger Live.
