# Ledger Hardware Wallet Support

Electron Radiant supports Ledger hardware wallets using the standard **Bitcoin app** already
installed on your device. No custom Radiant app is required, and no contact with Ledger is needed.

Supported devices: **Nano S**, **Nano S Plus**, **Nano X**, **Stax**, **Flex**, and all compatible
Ledger models (vendor ID `0x2c97`).

| Device | Bitcoin app required |
|---|---|
| Nano S (original) | v1.x or v2.0.x (legacy protocol) |
| Nano X | v2.1+ (new protocol, auto-detected) |
| Nano S Plus | v2.1+ (new protocol, auto-detected) |
| Stax | v2.1+ (new protocol, auto-detected) |
| Flex | v2.1+ (new protocol, auto-detected) |

Electron Radiant automatically detects which protocol your device uses and switches between
the legacy `btchip` path and the new PSBT-based `ledger_bitcoin` path accordingly. No
configuration is needed.

---

## How It Works

Radiant (RXD) uses the same elliptic curve cryptography (secp256k1) and transaction signing
scheme as Bitcoin — specifically `SIGHASH_ALL | SIGHASH_FORKID` (0x41). The Ledger Bitcoin
app is capable of performing this signing operation correctly, which is why no dedicated Radiant
app is needed.

The Ledger device will display **"Bitcoin"** branding on-screen during signing. This is expected —
the signatures it produces are fully valid for Radiant transactions.

---

## Will This Affect My Bitcoin Funds?

**No.** Your Bitcoin and Radiant funds are completely isolated:

- **Different derivation paths** — Electron Radiant derives keys at a different BIP32 path than
  Ledger Live or any Bitcoin wallet. The same physical device produces entirely different key
  pairs for each coin, so addresses never overlap.
- **Separate wallet files** — Electron Radiant maintains its own wallet files independent of
  Ledger Live or any other wallet software. No shared UTXOs or balances.
- **No cross-contamination possible** — Signing a Radiant transaction cannot affect, move, or
  expose any Bitcoin funds on the same device.

---

## Prerequisites

Before connecting your Ledger to Electron Radiant, ensure the following are installed:

```bash
pip install ledger_bitcoin ledgercomm hidapi
```

These provide:
- `ledger_bitcoin` — the modern Ledger Bitcoin app protocol library (app v2.1+, all current devices)
- `ledgercomm` — USB/HID transport layer used by `ledger_bitcoin`
- `hidapi` — low-level USB HID access (required by both protocol paths)

The `ledger_bitcoin` package also bundles the legacy `btchip` protocol internally, so no
separate `btchip-python` install is needed.

You can verify the installation by running:

```bash
python3 -c "import ledger_bitcoin; import hid; print('OK')"
```

---

## Setup Instructions

1. **Install dependencies** (see Prerequisites above).
2. **Connect your Ledger** via USB and unlock it with your PIN.
3. **Open the Bitcoin app** on the Ledger device.
4. **Launch Electron Radiant**.
5. Go to **File → New/Restore Wallet**, enter a wallet name, and click **Next**.
6. Select **Standard wallet** and click **Next**.
7. Select **Use a hardware device** and click **Next**.
8. Select **Ledger** from the list of hardware wallet types.
9. Follow the on-screen prompts. Electron Radiant will derive your Radiant addresses from
   the device and display them for confirmation.

> **Tip:** If the wallet wizard does not detect your Ledger, make sure:
> - The Bitcoin app is open on the device (not the dashboard).
> - No other application (e.g. Ledger Live) is currently connected to the device.
> - On Linux, udev rules for Ledger are installed (see below).
> - The `btchip-python` library is installed (`pip install btchip-python`). Without this library, the "Use a hardware device" option will not appear.

---

## Linux: udev Rules

On Linux you may need to add udev rules so that your user account can access the Ledger USB
device without `sudo`. Ledger provides an official installer:

```bash
wget -q -O - https://raw.githubusercontent.com/LedgerHQ/udev-rules/master/add_udev_rules.sh | sudo bash
```

After running this, unplug and replug the Ledger device, then try again.

---

## Sending a Transaction

1. Build and review your transaction in the **Send** tab as normal.
2. When you click **Send**, Electron Radiant will instruct the Ledger to sign.
3. The Ledger device will display the transaction details — **review them on the device screen**.
4. Confirm on the device by pressing the physical button(s).
5. The signed transaction is broadcast automatically.

> The device will show the output amount and destination address for each output.
> Always verify these match what you entered in the wallet before confirming on the device.

---

## Showing a Receive Address

To verify a receive address on the device screen (recommended before receiving large amounts):

1. Go to the **Addresses** tab in Electron Radiant.
2. Right-click any address and choose **"Show on device"**.
3. The address will be displayed on the Ledger screen — confirm it matches what the wallet shows.

---

## Firmware Requirements

| Feature | Minimum Firmware |
|---|---|
| Basic signing (Nano S / HW1) | 1.0.4 |
| Full Bitcoin app support | 1.1.8 |
| Multiple outputs in one tx | 1.1.4 |
| Trusted inputs required | 1.4.0+ |
| Nano X USB support | Any current firmware |

If your firmware is too old, Electron Radiant will show an error with a link to update via
[https://www.ledgerwallet.com](https://www.ledgerwallet.com).

---

## Troubleshooting

| Problem | Solution |
|---|---|
| "Ledger not detected" | Make sure the Bitcoin app is open on the device, not the dashboard |
| "Not in Bitcoin mode" | Close other apps on the device and open the Bitcoin app |
| "Temporarily locked" | Unplug and replug the device, reopen the Bitcoin app |
| "Invalid channel" | Disable "Browser support" in the Bitcoin app settings on the device (Nano S only) |
| "Wallet locked" | Enter your PIN on the device to unlock it |
| Device not found on Linux | Install udev rules (see Linux section above) |
| `ImportError: No module named 'hid'` | Run `pip install hidapi` |
| `ImportError: No module named 'ledger_bitcoin'` | Run `pip install ledger_bitcoin ledgercomm` |
| **"Use a hardware device" option not showing** | Ensure `ledger_bitcoin` is installed. The option only appears when the Ledger library is available. See Prerequisites above. |
| Modern device (Nano X / S Plus / Stax / Flex) not signing | Ensure you are running Ledger Bitcoin app v2.1 or newer on the device |

---

## Security Notes

- **Never share your 24-word recovery phrase** with anyone, including Electron Radiant support.
  The seed phrase never leaves the device and is never needed by the wallet software.
- The Ledger device is the source of truth for your private keys. Even if the Electron Radiant
  wallet file is lost or corrupted, your funds are recoverable from the device seed phrase.
- Always **verify transaction details on the device screen** before confirming. The wallet
  software running on your computer could theoretically be compromised; the device screen
  cannot be manipulated remotely.

---

## Technical Details

For developers or advanced users:

- **Signing**: `sighashType = 0x41` (`SIGHASH_ALL | SIGHASH_FORKID`) — set in
  `electroncash_plugins/ledger/ledger.py` for both protocol paths
- **Legacy protocol** (app v1.x / v2.0): USB HID via `btchip` APDU protocol (`Ledger_Client_Legacy`)
- **New protocol** (app v2.1+): PSBT-based signing via `ledger_bitcoin` library (`Ledger_Client_New`)
- **Auto-detection**: `LedgerPlugin.create_client()` probes the device and chooses the correct client automatically
- **Key derivation**: BIP32/BIP44 derivation performed on-device, path configured in wallet setup
- **Plugin location**: `electroncash_plugins/ledger/`
- **SIGHASH_FORKID injection**: For the new PSBT path, `0x41` is written into `PSBT_IN_SIGHASH_TYPE` per input before `sign_psbt()` is called
