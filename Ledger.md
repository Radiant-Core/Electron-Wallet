# Ledger Hardware Wallet Support

Electron Radiant supports Ledger hardware wallets using the standard **Bitcoin app** already
installed on your device. No custom Radiant app is required, and no contact with Ledger is needed.

Supported devices: **Nano S**, **Nano S Plus**, **Nano X**, and compatible Ledger models.

---

## How It Works

Radiant (RXD) uses the same elliptic curve cryptography (secp256k1) and transaction signing
scheme as Bitcoin Cash — specifically `SIGHASH_ALL | SIGHASH_FORKID` (0x41). The Ledger Bitcoin
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
pip install btchip-python hidapi
```

These provide the USB HID communication layer (`hid`) and Ledger protocol library (`btchip`)
required by the Ledger plugin. Without them, the plugin will silently skip loading.

You can verify they are available by running:

```bash
python3 -c "import hid; from btchip.btchip import btchip; print('OK')"
```

---

## Setup Instructions

1. **Install dependencies** (see Prerequisites above).
2. **Connect your Ledger** via USB and unlock it with your PIN.
3. **Open the Bitcoin app** on the Ledger device.
4. **Launch Electron Radiant**.
5. Go to **File → New/Restore Wallet** and choose **"Hardware wallet"**.
6. Select **Ledger** from the list of hardware wallet types.
7. Follow the on-screen prompts. Electron Radiant will derive your Radiant addresses from
   the device and display them for confirmation.

> **Tip:** If the wallet wizard does not detect your Ledger, make sure:
> - The Bitcoin app is open on the device (not the dashboard).
> - No other application (e.g. Ledger Live) is currently connected to the device.
> - On Linux, udev rules for Ledger are installed (see below).

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
| "Invalid channel" | Disable "Browser support" in the Bitcoin app settings on the device |
| "Wallet locked" | Enter your PIN on the device to unlock it |
| Device not found on Linux | Install udev rules (see Linux section above) |
| `ImportError: No module named 'hid'` | Run `pip install hidapi` |
| `ImportError: No module named 'btchip'` | Run `pip install btchip-python` |

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
  `electroncash_plugins/ledger/ledger.py`
- **Communication**: USB HID via `btchip-python` library
- **Key derivation**: BIP32/BIP44 derivation performed on-device, path configured in wallet setup
- **Plugin location**: `electroncash_plugins/ledger/`
- **Protocol**: Ledger APDU protocol via `btchip.btchip`
