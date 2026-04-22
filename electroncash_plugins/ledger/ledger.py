from struct import pack, unpack
import hashlib
import sys
import traceback

from electroncash import bitcoin
from electroncash.address import Address, OpCodes
from electroncash.bitcoin import TYPE_ADDRESS, TYPE_SCRIPT, int_to_hex, var_int
from electroncash.i18n import _
from electroncash.plugins import BasePlugin
from electroncash.keystore import Hardware_KeyStore
from electroncash.transaction import Transaction, InputValueMissing
from ..hw_wallet import HW_PluginBase
from ..hw_wallet.plugin import is_any_tx_output_on_change_branch, validate_op_return_output_and_get_data
from electroncash.util import print_error, is_verbose, bfh, bh2u, versiontuple

# ---------------------------------------------------------------------------
# Library imports — try the new ledger_bitcoin stack first, then fall back to
# the legacy btchip-python package for very old app versions.
# ---------------------------------------------------------------------------

LEDGER_BITCOIN = False   # new library (app v2.1+)
BTCHIP = False           # legacy library (app v1.x / v2.0)
BTCHIP_DEBUG = is_verbose

try:
    import ledger_bitcoin
    from ledger_bitcoin import WalletPolicy, AddressType, Chain
    from ledger_bitcoin.exception.errors import DenyError, NotSupportedError
    try:
        from ledger_bitcoin.exception.errors import SecurityStatusNotSatisfiedError
    except ImportError:
        SecurityStatusNotSatisfiedError = Exception
    from ledger_bitcoin.key import KeyOriginInfo
    from ledgercomm.interfaces.hid_device import HID

    # btchip is bundled inside ledger_bitcoin for the legacy path
    import hid
    from ledger_bitcoin.btchip.btchipComm import HIDDongleHIDAPI
    from ledger_bitcoin.btchip.btchip import btchip
    from ledger_bitcoin.btchip.btchipUtils import compress_public_key
    from ledger_bitcoin.btchip.bitcoinTransaction import bitcoinTransaction
    from ledger_bitcoin.btchip.btchipException import BTChipException

    LEDGER_BITCOIN = True
    BTCHIP = True
except ImportError:
    # Fall back: try standalone btchip-python (supports only legacy app v1.x)
    try:
        import hid
        from btchip.btchipComm import HIDDongleHIDAPI
        from btchip.btchip import btchip
        from btchip.btchipUtils import compress_public_key
        from btchip.bitcoinTransaction import bitcoinTransaction
        from btchip.btchipFirmwareWizard import checkFirmware
        from btchip.btchipException import BTChipException
        BTCHIP = True
    except ImportError:
        pass

# ---------------------------------------------------------------------------
# Version constants used by the legacy path
# ---------------------------------------------------------------------------

MULTI_OUTPUT_SUPPORT    = (1, 1, 4)
TRUSTED_INPUTS_REQUIRED = (1, 4, 0)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _parse_asn1_sig(signature):
    """Convert raw DER signature bytes from Ledger into the compact (r, s) form
    used by Electron Cash transaction signing."""
    rLength = signature[3]
    r = signature[4: 4 + rLength]
    sLength = signature[4 + rLength + 1]
    s = signature[4 + rLength + 2:]
    if rLength == 33:
        r = r[1:]
    if sLength == 33:
        s = s[1:]
    # Pad to 32 bytes
    r = bytes(32 - len(r)) + r
    s = bytes(32 - len(s)) + s
    return r, s


def test_pin_unlocked(func):
    """Decorator: catches a locked-device error and raises a readable message."""
    def catch_exception(self, *args, **kwargs):
        try:
            return func(self, *args, **kwargs)
        except Exception as e:
            if BTCHIP and isinstance(e, BTChipException):
                if e.sw == 0x5515:
                    raise Exception(
                        '0x5515 — ' + _('Hardware device is locked / PIN required.')
                        + '\n\n' + _('Please unlock your {} and open the Bitcoin Cash app, '
                                     'then re-open this wallet window.').format(self.device)
                    ) from e
                if e.sw in (0x6702, 0x6d00, 0x6700):
                    raise Exception(
                        '{:#06x} — '.format(e.sw)
                        + _('{} not in Bitcoin Cash mode. Please open the Bitcoin Cash app on your device.').format(self.device)
                    ) from e
                if e.sw in (0x6982, 0x6f04):
                    raise Exception(
                        _('Your {} is locked. Please unlock it.').format(self.device)
                        + '\n\n' + _('After unlocking, you may also need to re-open this wallet window.')
                    ) from e
            if LEDGER_BITCOIN and isinstance(e, SecurityStatusNotSatisfiedError):
                raise Exception(_('Your Ledger is locked. Please unlock it.')) from e
            raise
    return catch_exception


# ---------------------------------------------------------------------------
# Legacy client — Ledger Bitcoin app v1.x / v2.0.x (btchip protocol)
# ---------------------------------------------------------------------------

class Ledger_Client_Legacy:
    """Wraps the btchip library.  Works with Ledger Bitcoin app ≤ 2.0.x."""

    is_legacy = True

    def __init__(self, plugin, hidDevice, isHW1=False):
        self.device = plugin.device
        self.handler = None
        self.dongleObject = btchip(hidDevice)
        self.preflightDone = False
        self.isHW1 = isHW1

    def is_pairable(self):
        return True

    def close(self):
        self.dongleObject.dongle.close()

    def timeout(self, cutoff):
        pass

    def is_initialized(self):
        return True

    def label(self):
        return ""

    def is_hw1(self):
        return self.isHW1

    def i4b(self, x):
        return pack('>I', x)

    def has_usable_connection_with_device(self):
        try:
            self.dongleObject.getFirmwareVersion()
        except BTChipException as e:
            if e.sw == 0x6700:
                return True
            return False
        except BaseException:
            return False
        return True

    @test_pin_unlocked
    def get_xpub(self, bip32_path, xtype):
        self.checkDevice()
        splitPath = bip32_path.split('/')
        if splitPath[0] == 'm':
            splitPath = splitPath[1:]
            bip32_path = bip32_path[2:]
        fingerprint = 0
        if len(splitPath) > 1:
            prevPath = "/".join(splitPath[0:len(splitPath) - 1])
            nodeData = self.dongleObject.getWalletPublicKey(prevPath)
            publicKey = compress_public_key(nodeData['publicKey'])
            h = hashlib.new('ripemd160')
            h.update(hashlib.sha256(publicKey).digest())
            fingerprint = unpack(">I", h.digest()[0:4])[0]
        nodeData = self.dongleObject.getWalletPublicKey(bip32_path)
        publicKey = compress_public_key(nodeData['publicKey'])
        depth = len(splitPath)
        lastChild = splitPath[len(splitPath) - 1].split('\'')
        childnum = int(lastChild[0]) if len(lastChild) == 1 else 0x80000000 | int(lastChild[0])
        xpub = bitcoin.serialize_xpub(xtype, nodeData['chainCode'], publicKey, depth,
                                      self.i4b(fingerprint), self.i4b(childnum))
        return xpub

    def has_detached_pin_support(self, client):
        try:
            client.getVerifyPinRemainingAttempts()
            return True
        except AttributeError:
            return False  # bundled btchip; PIN is handled by device itself
        except BTChipException as e:
            if e.sw == 0x6d00:
                return False
            raise e

    def is_pin_validated(self, client):
        try:
            client.dongle.exchange(bytearray([0xe0, 0x26, 0x00, 0x00, 0x01, 0xAB]))
        except BTChipException as e:
            if e.sw == 0x6982:
                return False
            if e.sw == 0x6A80:
                return True
            raise e

    def supports_multi_output(self):
        return self.multiOutputSupported

    def requires_trusted_inputs(self):
        # Radiant uses SHA512/256d (not SHA256d) for txid hashing, so
        # getTrustedInput would compute the wrong hash.  Always use the
        # witness/value-embedding path (cashAddr=True, p2=0x03) which embeds
        # the UTXO amount directly for the BIP143 preimage without needing
        # the device to re-hash the previous transaction.
        return False

    def perform_hw1_preflight(self):
        try:
            firmwareInfo = self.dongleObject.getFirmwareVersion()
            firmwareVersion = versiontuple(firmwareInfo['version'])
            self.multiOutputSupported = firmwareVersion >= MULTI_OUTPUT_SUPPORT
            self.trustedInputsRequired = firmwareVersion >= TRUSTED_INPUTS_REQUIRED

            # checkFirmware only exists in standalone btchip-python; skip when
            # using the bundled copy inside ledger_bitcoin.
            try:
                from btchip.btchipFirmwareWizard import checkFirmware
                if not checkFirmware(firmwareInfo):
                    self.dongleObject.dongle.close()
                    raise Exception(
                        _("{} firmware version too old. Please update at https://www.ledgerwallet.com").format(self.device))
            except ImportError:
                pass

            try:
                self.dongleObject.getOperationMode()
            except AttributeError:
                pass  # bundled btchip doesn't have getOperationMode; skip
            except BTChipException as e:
                if e.sw == 0x6985:
                    self.dongleObject.dongle.close()
                    self.handler.get_setup()
                else:
                    raise e
            if (self.has_detached_pin_support(self.dongleObject)
                    and not self.is_pin_validated(self.dongleObject)
                    and self.handler is not None):
                remaining_attempts = self.dongleObject.getVerifyPinRemainingAttempts()
                if remaining_attempts != 1:
                    msg = _('Enter your {} PIN - remaining attempts: {}').format(self.device, remaining_attempts)
                else:
                    msg = _('Enter your {} PIN - WARNING: LAST ATTEMPT. If the PIN is not correct, '
                            'the {} will be wiped.').format(self.device, self.device)
                confirmed, p, pin = self.password_dialog(msg)
                if not confirmed:
                    raise Exception(
                        _('Aborted by user - please unplug the {hw_device_name} and plug it in again '
                          'before retrying').format(hw_device_name=self.device))
                pin = pin.encode()
                self.dongleObject.verifyPin(pin)
        except BTChipException as e:
            if e.sw == 0x6faa:
                raise Exception(
                    _("{hw_device_name} is temporarily locked - please unplug and plug it in again."
                      "\n\nIf this problem persists please exit and restart the Bitcoin "
                      "application running on the device.\n\nYou may also need to re-open this "
                      "wallet window as well.").format(hw_device_name=self.device)) from e
            if (e.sw & 0xFFF0) == 0x63c0:
                raise Exception(
                    _('Invalid PIN - please unplug the {hw_device_name} and plug it in again '
                      'before retrying').format(hw_device_name=self.device)) from e
            if e.sw == 0x6f00 and e.message == 'Invalid channel':
                raise Exception(
                    _('Invalid channel.') + '\n'
                    + _("Please make sure that 'Browser support' is disabled on your {}.").format(self.device)) from e
            raise e

    def checkDevice(self):
        if not self.preflightDone:
            try:
                self.perform_hw1_preflight()
            except BTChipException as e:
                if e.sw == 0x5515:
                    raise BaseException(
                        '0x5515 — ' + _('Hardware device is locked / PIN required.')
                        + '\n\n' + _('Please unlock your {} and open the Bitcoin Cash app, '
                                     'then re-open this wallet window.').format(self.device)) from e
                if e.sw in (0x6d00, 0x6700, 0x6702):
                    raise BaseException(
                        _('{} not in Bitcoin Cash mode. Please open the Bitcoin Cash app on your device.').format(self.device)) from e
                raise e
            self.preflightDone = True

    def password_dialog(self, msg=None):
        response = self.handler.get_word(msg)
        if response is None:
            return False, None, None
        return True, response, response


# ---------------------------------------------------------------------------
# New client — Ledger Bitcoin app v2.1+ (ledger_bitcoin / PSBT protocol)
# ---------------------------------------------------------------------------

class Ledger_Client_New:
    """Wraps the ledger_bitcoin library.  Works with Ledger Bitcoin app ≥ 2.1.x.
    This covers all current production devices: Nano X, Nano S Plus, Stax, Flex.

    Signing uses the PSBT flow.  Because Radiant requires SIGHASH_ALL|SIGHASH_FORKID
    (0x41) we inject the sighash type into each PSBT input before calling sign_psbt().
    The ledger_bitcoin library forwards whatever sighash type it finds in
    PSBT_IN_SIGHASH_TYPE (key 0x03) directly to the device, so the device will
    sign with 0x41 and produce a valid Radiant signature.
    """

    is_legacy = False

    # SIGHASH_ALL | SIGHASH_FORKID
    SIGHASH_FORKID = 0x41

    def __init__(self, plugin, new_client):
        """new_client: an already-constructed ledger_bitcoin.client.NewClient instance."""
        self.device = plugin.device
        self.handler = None
        self.client = new_client
        self._known_xpubs = {}
        self._registered_policies = {}

    def is_pairable(self):
        return True

    def close(self):
        try:
            self.client.stop()
        except Exception:
            pass

    def timeout(self, cutoff):
        pass

    def is_initialized(self):
        return True

    def label(self):
        return ""

    def checkDevice(self):
        pass  # no preflight needed for new client; device must have Bitcoin app open

    def has_usable_connection_with_device(self):
        try:
            self.client.get_version()
            return True
        except Exception:
            return False

    def get_master_fingerprint(self):
        return self.client.get_master_fingerprint()

    @test_pin_unlocked
    def get_xpub(self, bip32_path, xtype):
        """Derive an xpub from the device.  The new app always returns standard
        (xpub) serialisation; we reuse bitcoin.serialize_xpub to convert to the
        xtype the caller wants.
        """
        bip32_path = bip32_path.replace('h', "'")
        if bip32_path in self._known_xpubs:
            raw_xpub = self._known_xpubs[bip32_path]
        else:
            try:
                raw_xpub = self.client.get_extended_pubkey(bip32_path)
            except NotSupportedError:
                # non-standard path: display on screen so user can confirm
                raw_xpub = self.client.get_extended_pubkey(bip32_path, True)
            self._known_xpubs[bip32_path] = raw_xpub

        if xtype == 'standard':
            return raw_xpub

        # Re-serialise with the correct version bytes for the requested xtype
        from electroncash.bitcoin import deserialize_xpub, serialize_xpub
        _xtype, depth, fingerprint, child_number, chaincode, pubkey = deserialize_xpub(raw_xpub)
        return serialize_xpub(xtype, chaincode, pubkey, depth, fingerprint, child_number)

    def _get_singlesig_policy(self, bip32_path):
        """Build a pkh(@0/**) WalletPolicy for a standard BIP-44 P2PKH account path.

        bip32_path must be the *account* root, e.g. "44'/0'/0'" (without m/).
        """
        fpr = self.get_master_fingerprint()
        xpub = self.get_xpub('m/' + bip32_path, 'standard')
        key_info = "[{}/{}]{}".format(fpr.hex(), bip32_path, xpub)
        return WalletPolicy(name="", descriptor_template="pkh(@0/**)", keys_info=[key_info])

    def _register_policy_if_needed(self, wallet_policy):
        """Register a non-standard wallet policy and cache the hmac."""
        if wallet_policy.id not in self._registered_policies:
            wallet_id, wallet_hmac = self.client.register_wallet(wallet_policy)
            self._registered_policies[wallet_id] = wallet_hmac
        return wallet_policy.id, self._registered_policies[wallet_policy.id]

    @test_pin_unlocked
    def show_address(self, address_path, showOnScreen=True):
        """Display an address on the Ledger screen for user verification.

        address_path: full path without leading "m/", e.g. "44'/0'/0'/0/3"
        """
        self.handler.show_message(_('Showing address on {}...').format(self.device))
        try:
            parts = address_path.split('/')
            if len(parts) < 2:
                raise Exception("Address path too short")
            change = int(parts[-2])
            addr_index = int(parts[-1])
            account_path = '/'.join(parts[:-2])
            policy = self._get_singlesig_policy(account_path)

            wallet_hmac = None
            # Standard BIP-44 paths do not need registration
            if policy.name != "":
                __, wallet_hmac = self._register_policy_if_needed(policy)

            self.client.get_wallet_address(policy, wallet_hmac, change, addr_index, showOnScreen)
        except DenyError:
            pass  # cancelled by user
        except BaseException as e:
            traceback.print_exc(file=sys.stderr)
            self.handler.show_error(str(e))
        finally:
            self.handler.finished()

    @test_pin_unlocked
    def sign_transaction(self, tx, password, signing_info):
        """Sign a Radiant transaction using PSBTv2 and the custom app-radiant firmware.

        Constructs a PSBTv2 with SIGHASH_FORKID|SIGHASH_ALL (0x41) per input,
        sets witness_utxo (amount + scriptPubKey) and non_witness_utxo (full prev tx
        so the device can verify the txid), and uses a standard pkh(@0/**) wallet
        policy matching Electron Wallet's m/44'/0'/0' derivation.

        signing_info: list of (signing_pos, full_path, pubkey_hex, prev_tx_raw,
                               prevout_n, redeem_script_hex, sequence, amount)
                      as built by Ledger_KeyStore.sign_transaction.
        """
        if tx.is_complete():
            return

        print_error(f"[Ledger] Ledger_Client_New.sign_transaction (PSBTv2): {len(signing_info)} inputs")

        try:
            from ledger_bitcoin.psbt import PSBT, PartiallySignedInput, PartiallySignedOutput
            from ledger_bitcoin.tx import CTxOut, CTransaction
            from io import BytesIO

            fpr = self.get_master_fingerprint()

            # --- Build PSBTv2 ---
            psbt = PSBT()
            psbt.version = 2
            psbt.explicit_version = True
            psbt.tx_version = tx.version
            psbt.fallback_locktime = tx.locktime

            # --- Populate inputs ---
            for idx, info in enumerate(signing_info):
                (signing_pos, full_path, pubkey_hex,
                 prev_tx_raw, prevout_n, redeem_script_hex, sequence, amount) = info

                psbt_in = PartiallySignedInput(version=2)

                # prev_txid: 32-byte little-endian txid bytes
                # prevout_hash is the display hex (reversed); reverse back to LE bytes
                txin = tx.inputs()[idx]
                prevout_hash_le = bfh(txin['prevout_hash'])[::-1]
                psbt_in.prev_txid = prevout_hash_le
                psbt_in.prev_out = prevout_n
                psbt_in.sequence = sequence

                # SIGHASH_FORKID | SIGHASH_ALL — required for Radiant
                psbt_in.sighash = self.SIGHASH_FORKID

                # witness_utxo: amount (satoshis) + scriptPubKey of the spent output
                # redeemScript from Electron is already the scriptPubKey for P2PKH
                script_pubkey = bfh(redeem_script_hex)
                # For P2PKH inputs the "redeemScript" IS the scriptPubKey;
                # amount comes from the txin dict (set by wallet from UTXO)
                utxo_amount = txin.get('value', amount)  # satoshis
                psbt_in.witness_utxo = CTxOut(nValue=utxo_amount, scriptPubKey=script_pubkey)

                # non_witness_utxo: full previous transaction so the device can
                # verify SHA256d(rawTx) == prevTxid (prevents fee manipulation).
                if prev_tx_raw:
                    prev_ctx = CTransaction()
                    prev_ctx.deserialize(BytesIO(bfh(prev_tx_raw)))
                    prev_ctx.rehash()
                    psbt_in.non_witness_utxo = prev_ctx

                # BIP-32 derivation path — full path e.g. "44'/0'/0'/0/3"
                path_parts = full_path.replace('h', "'").split('/')
                int_path = []
                for part in path_parts:
                    if part.endswith("'"):
                        int_path.append(0x80000000 | int(part[:-1]))
                    else:
                        int_path.append(int(part))
                pubkey_bytes = bfh(pubkey_hex)
                psbt_in.hd_keypaths[pubkey_bytes] = KeyOriginInfo(fpr, int_path)

                psbt.inputs.append(psbt_in)

            # --- Populate outputs ---
            for _type, addr, out_amount in tx.outputs():
                psbt_out = PartiallySignedOutput(version=2)
                psbt_out.amount = out_amount
                psbt_out.script = bfh(tx.pay_script(addr))
                psbt.outputs.append(psbt_out)

            # --- Wallet policy: pkh(@0/**) at the account path (m/44'/0'/0') ---
            # Strip last 2 path components (change/index) to get account path.
            first_path = signing_info[0][1]  # e.g. "44'/0'/0'/0/3"
            account_path = '/'.join(first_path.split('/')[:-2])  # "44'/0'/0'"
            policy = self._get_singlesig_policy(account_path)

            print_error(f"[Ledger] policy={policy.descriptor_template} keys={policy.keys_info}")

            wallet_hmac = None
            if policy.name != "":
                __, wallet_hmac = self._register_policy_if_needed(policy)

            self.handler.show_message(_('Confirm Transaction on your {}...').format(self.device))
            input_sigs = self.client.sign_psbt(psbt, policy, wallet_hmac)

            # --- Verify each signature locally before writing to the tx ---
            # (B1 security fix) Recompute the Radiant sighash preimage from the
            # wallet-side tx object and verify the device-returned DER signature
            # against it.  Catches any firmware/wallet sighash divergence
            # (hashOutputHashes mismatch, ref-sort drift, compromised firmware)
            # before broadcast instead of producing a silently invalid tx.
            from electroncash.bitcoin import Hash as _sha256d
            for sig_idx, part_sig in input_sigs:
                txin = tx.inputs()[sig_idx]
                signing_pos = signing_info[sig_idx][0]
                sig_bytes = bytes(part_sig.signature)
                # Device appends sighash byte 0x41; normalise in case it used 0x01
                if sig_bytes and sig_bytes[-1] in (0x01, 0x41):
                    der_sig = sig_bytes[:-1]
                else:
                    der_sig = sig_bytes
                sig_with_hashtype = der_sig + bytes([self.SIGHASH_FORKID])

                # Recompute sighash preimage using the wallet's own tx object
                try:
                    preimage_hex = tx.serialize_preimage(sig_idx, self.SIGHASH_FORKID)
                    msghash = _sha256d(bfh(preimage_hex))
                    pubkey_hex = signing_info[sig_idx][2]
                    pubkey_bytes = bfh(pubkey_hex) if isinstance(pubkey_hex, str) else pubkey_hex
                    reasons = []
                    if not Transaction.verify_signature(pubkey_bytes, der_sig, msghash,
                                                        reason=reasons):
                        why = '; '.join(reasons) if reasons else 'signature invalid'
                        raise Exception(
                            _('Ledger signature for input {idx} did not verify locally '
                              'against the wallet-computed sighash (reason: {why}). '
                              'The device signed a different message than the wallet '
                              'built. DO NOT broadcast — this is a firmware or wallet '
                              'bug and should be reported.').format(idx=sig_idx, why=why))
                except InputValueMissing:
                    # input value not cached; skip local verification for this input
                    print_error(f"[Ledger] skipping local verify for input {sig_idx}: input value missing")

                txin['signatures'][signing_pos] = bh2u(sig_with_hashtype)

            tx.raw = tx.serialize()

        except DenyError:
            self.handler.show_error(_('Cancelled by user'))
        except BaseException as e:
            traceback.print_exc(file=sys.stderr)
            self.handler.show_error(str(e))
        finally:
            self.handler.finished()
    
    
    @test_pin_unlocked
    def sign_message(self, address_path, message, password):
        """Sign a message using the new ledger_bitcoin API."""
        import base64
        message_bytes = message.encode('utf8') if isinstance(message, str) else message
        message_hash = hashlib.sha256(message_bytes).hexdigest().upper()
        self.handler.show_message(
            _('Signing message...') + '\n' + _('Message hash: {}').format(message_hash))
        try:
            sig_str = self.client.sign_message(message_bytes, 'm/' + address_path)
            result = base64.b64decode(sig_str, validate=True)
        except DenyError:
            self.handler.show_error(_('Cancelled by user'))
            result = b''
        except BaseException as e:
            traceback.print_exc(file=sys.stderr)
            self.handler.show_error(str(e))
            result = b''
        finally:
            self.handler.finished()
        return result


# ---------------------------------------------------------------------------
# KeyStore — shared logic on top of whichever client is active
# ---------------------------------------------------------------------------

class Ledger_KeyStore(Hardware_KeyStore):
    hw_type = 'ledger'
    device = 'Ledger'

    def __init__(self, d):
        Hardware_KeyStore.__init__(self, d)
        self.force_watching_only = False
        self.signing = False
        self.cfg = d.get('cfg', {'mode': 0})

    def dump(self):
        obj = Hardware_KeyStore.dump(self)
        obj['cfg'] = self.cfg
        return obj

    def get_derivation(self):
        return self.derivation

    def get_client(self):
        """Return the raw dongle object (legacy) or the new client object."""
        client = self.plugin.get_client(self)
        if isinstance(client, Ledger_Client_Legacy):
            return client.dongleObject
        return client  # Ledger_Client_New exposes its own API

    def get_client_wrapper(self):
        """Return the Ledger_Client_Legacy or Ledger_Client_New wrapper."""
        return self.plugin.get_client(self)

    def give_error(self, message, clear_client=False):
        print_error(message)
        if not self.signing:
            self.handler.show_error(message)
        else:
            self.signing = False
        if clear_client:
            self.client = None
        raise Exception(message)

    def set_and_unset_signing(func):
        """Function decorator to set and unset self.signing."""
        def wrapper(self, *args, **kwargs):
            try:
                self.signing = True
                return func(self, *args, **kwargs)
            finally:
                self.signing = False
        return wrapper

    def address_id_stripped(self, address):
        change, index = self.get_address_index(address)
        derivation = self.derivation
        address_path = "{:s}/{:d}/{:d}".format(derivation, change, index)
        return address_path[2:]

    def decrypt_message(self, pubkey, message, password):
        raise RuntimeError(
            _('Encryption and decryption are currently not supported for {}').format(self.device))

    @test_pin_unlocked
    @set_and_unset_signing
    def sign_message(self, sequence, message, password):
        client_wrapper = self.get_client_wrapper()
        address_path = self.get_derivation()[2:] + "/{:d}/{:d}".format(*sequence)

        if isinstance(client_wrapper, Ledger_Client_New):
            return client_wrapper.sign_message(address_path, message, password)

        # --- Legacy path ---
        message = message.encode('utf8') if isinstance(message, str) else message
        message_hash = hashlib.sha256(message).hexdigest().upper()
        client = client_wrapper.dongleObject
        self.handler.show_message(
            _('Signing message...') + '\n' + _('Message hash: {}').format(message_hash))
        try:
            info = client.signMessagePrepare(address_path, message)
            pin = ""
            if info['confirmationNeeded']:
                pin = self.handler.get_auth(info)
                if not pin:
                    raise UserWarning(_('Cancelled by user'))
                pin = str(pin).encode()
            signature = client.signMessageSign(pin)
        except BTChipException as e:
            if e.sw == 0x6a80:
                self.give_error(
                    _('Unfortunately, this message cannot be signed by the {}. '
                      'Only alphanumerical messages shorter than 140 characters are supported. '
                      'Please remove any extra characters (tab, carriage return) and retry.'
                      ).format(self.device))
            elif e.sw == 0x6985:
                return b''
            elif e.sw == 0x6982:
                raise
            else:
                self.give_error(e, True)
        except UserWarning:
            self.handler.show_error(_('Cancelled by user'))
            return b''
        except Exception as e:
            self.give_error(e, True)
        finally:
            self.handler.finished()
        r, s = _parse_asn1_sig(signature)
        return bytes([27 + 4 + (signature[0] & 0x01)]) + r + s

    @test_pin_unlocked
    @set_and_unset_signing
    def sign_transaction(self, tx, password, *, use_cache=False):
        if tx.is_complete():
            return

        client_wrapper = self.get_client_wrapper()

        # Build common input data needed by both paths
        inputs = []
        inputsPaths = []
        pubKeys = []
        p2shTransaction = False
        pin = ""

        derivations = self.get_tx_derivations(tx)
        for txin in tx.inputs():
            if txin['type'] == 'coinbase':
                self.give_error(_('Coinbase not supported'))

            if txin['type'] in ['p2sh']:
                p2shTransaction = True

            pubkeys, x_pubkeys = tx.get_sorted_pubkeys(txin)
            for i, x_pubkey in enumerate(x_pubkeys):
                if x_pubkey in derivations:
                    signingPos = i
                    s = derivations.get(x_pubkey)
                    hwAddress = "{:s}/{:d}/{:d}".format(self.get_derivation()[2:], s[0], s[1])
                    break
            else:
                self.give_error(_('No matching x_key for sign_transaction'))

            redeemScript = Transaction.get_preimage_script(txin)
            inputs.append([txin['prev_tx'].raw,
                           txin['prevout_n'],
                           redeemScript,
                           txin['prevout_hash'],
                           signingPos,
                           txin.get('sequence', 0xffffffff - 1),
                           hwAddress,
                           pubkeys[signingPos] if signingPos < len(pubkeys) else pubkeys[0]])
            inputsPaths.append(hwAddress)
            pubKeys.append(pubkeys)

        if p2shTransaction:
            for txin in tx.inputs():
                if txin['type'] != 'p2sh':
                    self.give_error(_('P2SH / regular input mixed in same transaction not supported'))

        # ----- New client path (Radiant custom app / app v2.1+) -----
        if isinstance(client_wrapper, Ledger_Client_New):
            signing_info = []
            wallet = getattr(self, 'wallet', None)
            network = wallet.network if wallet else None
            for i, inp in enumerate(inputs):
                prev_tx_raw, prevout_n, redeemScript, prevout_hash, signingPos, sequence, hwAddress, pubkey = inp
                # Fetch the correct raw prev tx from the network to ensure the
                # txid (Radiant SHA512/256d) matches prevout_hash exactly.
                # txin['prev_tx'].raw may be stale/wrong in the wallet cache.
                correct_raw = None
                print_error(f"[Ledger] fetching prev tx {prevout_hash}, network={network is not None}")
                if network:
                    try:
                        correct_raw = network.synchronous_get(
                            ('blockchain.transaction.get', [prevout_hash]), timeout=10)
                        print_error(f"[Ledger] fetched prev tx OK, len={len(correct_raw) if correct_raw else 0}")
                    except Exception as e:
                        print_error(f"[Ledger] could not fetch prev tx {prevout_hash}: {e}")
                if correct_raw is None:
                    print_error(f"[Ledger] using cached prev_tx_raw, len={len(prev_tx_raw) if prev_tx_raw else 0}")
                    correct_raw = prev_tx_raw  # fall back to cached
                utxo_value = tx.inputs()[i].get('value', 0)  # satoshis from UTXO set
                signing_info.append((
                    signingPos,        # position in multisig pubkey list
                    hwAddress,         # full path without m/
                    bh2u(pubkey) if isinstance(pubkey, (bytes, bytearray)) else pubkey,
                    correct_raw,
                    prevout_n,
                    redeemScript,
                    sequence,
                    utxo_value,        # UTXO amount in satoshis (for witness_utxo)
                ))
            client_wrapper.sign_transaction(tx, password, signing_info)
            return

        # ----- Legacy client path (app v1.x / v2.0) -----
        client = client_wrapper.dongleObject

        chipInputs = []
        redeemScripts = []
        signatures = []
        changePath = ""
        output = None

        txOutput = var_int(len(tx.outputs()))
        for txout in tx.outputs():
            output_type, addr, amount = txout
            txOutput += int_to_hex(amount, 8)
            script = tx.pay_script(addr)
            txOutput += var_int(len(script) // 2)
            txOutput += script
        txOutput = bfh(txOutput)

        if not p2shTransaction:
            if not client_wrapper.supports_multi_output():
                if len(tx.outputs()) > 2:
                    self.give_error(
                        _('Transaction with more than 2 outputs not supported by {}').format(self.device))
            has_change = False
            any_output_on_change_branch = is_any_tx_output_on_change_branch(tx)
            for o in tx.outputs():
                _type, address, amount = o
                if not _type in [TYPE_ADDRESS, TYPE_SCRIPT]:
                    self.give_error(
                        _('Only address and script outputs are supported by {}').format(self.device))
                if _type == TYPE_SCRIPT:
                    # (P5) Glyph FT/NFT outputs are TYPE_SCRIPT but are NOT
                    # OP_RETURN: they are reference-prefixed P2PKH scripts.
                    # Skip OP_RETURN validation for them; the Radiant firmware
                    # accepts the 75-byte / 63-byte templates natively.
                    from electroncash.glyph import GlyphFTOutput, GlyphNFTOutput
                    if not isinstance(address, (GlyphFTOutput, GlyphNFTOutput)):
                        try:
                            validate_op_return_output_and_get_data(o, max_size=187, max_pushes=None)
                        except RuntimeError as e:
                            self.give_error('{}: {}'.format(self.device, str(e)))
                info = tx.output_info.get(address)
                if info is not None and len(tx.outputs()) > 1 and not has_change:
                    index, xpubs, m, script_type = info
                    on_change_branch = index[0] == 1
                    if on_change_branch == any_output_on_change_branch:
                        changePath = self.get_derivation()[2:] + "/{:d}/{:d}".format(*index)
                        has_change = True
                    else:
                        output = address
                else:
                    output = address

        self.handler.show_message(_('Confirm Transaction on your {}...').format(self.device))
        try:
            for inp in inputs:
                prev_tx_raw, prevout_n, redeemScript, prevout_hash, signingPos, sequence, hwAddress, pubkey = inp
                sequence_hex = int_to_hex(sequence, 4)
                if not client_wrapper.requires_trusted_inputs():
                    txtmp = bitcoinTransaction(bfh(prev_tx_raw))
                    tmp = bfh(prevout_hash)[::-1]
                    tmp += bfh(int_to_hex(prevout_n, 4))
                    tmp += txtmp.outputs[prevout_n].amount
                    chipInputs.append({'value': tmp, 'witness': True, 'sequence': sequence_hex})
                    redeemScripts.append(bfh(redeemScript))
                else:
                    txtmp = bitcoinTransaction(bfh(prev_tx_raw))
                    trustedInput = client.getTrustedInput(txtmp, prevout_n)
                    trustedInput['sequence'] = sequence_hex
                    trustedInput['witness'] = True
                    chipInputs.append(trustedInput)
                    if p2shTransaction:
                        redeemScripts.append(bfh(redeemScript))
                    else:
                        redeemScripts.append(txtmp.outputs[prevout_n].script)

            inputIndex = 0
            try:
                client.enableAlternate2fa(False)
            except AttributeError:
                pass  # not available in bundled btchip
            client.startUntrustedTransaction(True, inputIndex,
                                             chipInputs, redeemScripts[inputIndex],
                                             cashAddr=True)
            outputData = client.finalizeInput(b'', 0, 0, changePath, bfh(tx.serialize(True)))
            outputData['outputData'] = txOutput
            if outputData['confirmationNeeded']:
                outputData['address'] = output
                self.handler.finished()
                pin = self.handler.get_auth(outputData)
                if not pin:
                    raise UserWarning()
                self.handler.show_message(_('Confirmed. Signing Transaction...'))
            while inputIndex < len(inputs):
                singleInput = [chipInputs[inputIndex]]
                client.startUntrustedTransaction(False, 0,
                                                 singleInput, redeemScripts[inputIndex],
                                                 cashAddr=True)
                inputSignature = client.untrustedHashSign(
                    inputsPaths[inputIndex], pin,
                    lockTime=tx.locktime,
                    sighashType=0x41)  # SIGHASH_ALL | SIGHASH_FORKID
                inputSignature[0] = 0x30  # force for 1.4.9+
                signatures.append(inputSignature)
                inputIndex += 1
        except UserWarning:
            self.handler.show_error(_('Cancelled by user'))
            return
        except BTChipException as e:
            if e.sw in (0x6985, 0x6d00):
                return
            elif e.sw == 0x6982:
                raise
            else:
                traceback.print_exc(file=sys.stderr)
                self.give_error(e, True)
        except BaseException as e:
            traceback.print_exc(file=sys.stdout)
            self.give_error(e, True)
        finally:
            self.handler.finished()

        for i, txin in enumerate(tx.inputs()):
            signingPos = inputs[i][4]
            txin['signatures'][signingPos] = bh2u(signatures[i])
        tx.raw = tx.serialize()

    @test_pin_unlocked
    @set_and_unset_signing
    def show_address(self, sequence):
        client_wrapper = self.get_client_wrapper()
        address_path = self.get_derivation()[2:] + "/{:d}/{:d}".format(*sequence)

        if isinstance(client_wrapper, Ledger_Client_New):
            client_wrapper.show_address(address_path)
            return

        # --- Legacy path ---
        client = client_wrapper.dongleObject
        self.handler.show_message(_('Showing address on {}...').format(self.device))
        try:
            client.getWalletPublicKey(address_path, showOnScreen=True)
        except BTChipException as e:
            if e.sw == 0x6985:
                pass
            elif e.sw == 0x6982:
                raise
            elif e.sw == 0x6b00:
                self.handler.show_error('{}\n{}\n{}'.format(
                    _('Error showing address') + ':',
                    e,
                    _('Your {} might not have support for this functionality.').format(self.device)))
            else:
                traceback.print_exc(file=sys.stderr)
                self.handler.show_error(e)
        except BaseException as e:
            traceback.print_exc(file=sys.stderr)
            self.handler.show_error(e)
        finally:
            self.handler.finished()


# ---------------------------------------------------------------------------
# Plugin
# ---------------------------------------------------------------------------

class LedgerPlugin(HW_PluginBase):
    libraries_available = BTCHIP or LEDGER_BITCOIN
    keystore_class = Ledger_KeyStore
    client = None

    # Explicit product keys for legacy devices (Nano S era and older)
    DEVICE_IDS = [
        (0x2581, 0x1807),  # HW.1 legacy btchip
        (0x2581, 0x2b7c),  # HW.1 transitional production
        (0x2581, 0x3b7c),  # HW.1 ledger production
        (0x2581, 0x4b7c),  # HW.1 ledger test
        (0x2c97, 0x0000),  # Blue
        (0x2c97, 0x0011),  # Blue app-bitcoin >= 1.5.1
        (0x2c97, 0x0015),  # Blue app-bitcoin >= 1.5.1
        (0x2c97, 0x0001),  # Nano S
        (0x2c97, 0x1011),  # Nano S app-bitcoin >= 1.5.1
        (0x2c97, 0x1015),  # Nano S app-bitcoin >= 1.5.1
        (0x2c97, 0x0004),  # Nano X
        (0x2c97, 0x4011),  # Nano X app-bitcoin >= 1.5.1
        (0x2c97, 0x4015),  # Nano X app-bitcoin >= 1.5.1
        (0x2c97, 0x0005),  # Nano S Plus
        (0x2c97, 0x5000),  # Nano S Plus (Bitcoin app open, newer firmware)
        (0x2c97, 0x5010),  # Nano S Plus app interface variant
        (0x2c97, 0x5011),  # Nano S Plus app-bitcoin >= 1.5.1
        (0x2c97, 0x5015),  # Nano S Plus app-bitcoin >= 1.5.1
        (0x2c97, 0x0006),  # Stax
        (0x2c97, 0x0007),  # Flex
        (0x2c97, 0x0008),  # Nano Gen5
        (0x2c97, 0x0009),  # RFU
        (0x2c97, 0x000a),  # RFU
    ]

    # Vendor-ID catch-all: any future 0x2c97 product will be probed
    VENDOR_IDS = (0x2c97,)

    def __init__(self, parent, config, name):
        HW_PluginBase.__init__(self, parent, config, name)
        if self.libraries_available:
            self.device_manager().register_devices(self.DEVICE_IDS)

    @staticmethod
    def is_hw1(product_key):
        return product_key[0] == 0x2581

    def can_recognize_device(self, device):
        """Accept any 0x2c97 device on interface 0 or usage-page 0xffa0.
        Multiple HID interfaces are exposed by modern Ledger devices;
        only interface 0 / usage-page 0xffa0 is the APDU channel we need.
        """
        if device.product_key in self.DEVICE_IDS:
            if device.product_key[0] == 0x2c97:
                return (device.interface_number == 0
                        or device.usage_page == 0xffa0)
            return True
        # Vendor catch-all for unrecognised 0x2c97 products
        if device.product_key[0] == 0x2c97:
            return (device.interface_number == 0
                    or device.usage_page == 0xffa0)
        return False

    def _open_hid(self, device):
        """Open a raw HID handle for the legacy btchip path."""
        is_ledger = (device.product_key[0] == 0x2c97
                     or device.product_key[1] in (0x3b7c, 0x4b7c))
        dev = hid.device()
        dev.open_path(device.path)
        dev.set_nonblocking(True)
        return HIDDongleHIDAPI(dev, is_ledger, BTCHIP_DEBUG)

    def _try_new_client(self, device):
        """Attempt to open the device using the new ledger_bitcoin library.

        Returns a tuple (result, hid_device):
          - (Ledger_Client_New, hid_device) : app v2.1+, use as-is
          - (None, hid_device)              : LegacyClient returned; caller MUST
                                             wrap hid_device in HIDDongleHIDAPI
                                             rather than re-opening the path
          - (None, None)                   : failed entirely, fall back however
        """
        if not LEDGER_BITCOIN:
            return None, None
        hid_device = HID()
        hid_device.path = device.path
        try:
            hid_device.open()
        except Exception:
            return None, None
        transport = ledger_bitcoin.TransportClient('hid', hid=hid_device)
        try:
            cl = ledger_bitcoin.createClient(transport, chain=Chain.MAIN)
        except Exception:
            try:
                hid_device.close()
            except Exception:
                pass
            return None, None
        if isinstance(cl, ledger_bitcoin.client.NewClient):
            # Probe the new client to confirm the app actually supports the
            # new Bitcoin app v2.1+ protocol.  The BCH app and old Bitcoin
            # app report version ≥ 2.1 but reject new-protocol APDUs with
            # 0x6e00 (ClaNotSupportedError).  Fall through to legacy in that
            # case so btchip handles signing with sighashType=0x41.
            try:
                from ledger_bitcoin.exception.errors import ClaNotSupportedError
                cl.get_master_fingerprint()
                return Ledger_Client_New(self, cl), hid_device
            except ClaNotSupportedError:
                print_error("[Ledger] NewClient probe failed (0x6e00) — falling back to legacy btchip (BCH app?)")
                # Fall through: treat as legacy
            except Exception:
                return Ledger_Client_New(self, cl), hid_device
        # LegacyClient returned (or NewClient probe failed) — keep hid_device
        # open for legacy btchip use.
        return None, hid_device

    def create_client(self, device, handler):
        self.handler = handler

        if not self.can_recognize_device(device):
            return None

        # Try the new protocol first (app 2.1+).
        # _try_new_client opens HID once and returns it so we never double-open.
        new_client, hid_device = self._try_new_client(device)
        if new_client is not None:
            new_client.handler = handler
            return new_client

        # Fall back to legacy btchip protocol
        if not BTCHIP:
            if hid_device is not None:
                try:
                    hid_device.close()
                except Exception:
                    pass
            return None
        try:
            if hid_device is not None:
                # Reuse the already-open HID handle — avoids re-opening and
                # changing the OS device ID between scan and registration.
                is_ledger = (device.product_key[0] == 0x2c97
                             or device.product_key[1] in (0x3b7c, 0x4b7c))
                raw_hid = hid_device.device  # underlying hid.device() handle
                hid_dongle = HIDDongleHIDAPI(raw_hid, is_ledger, BTCHIP_DEBUG)
            else:
                hid_dongle = self._open_hid(device)
        except Exception:
            return None
        ishw1 = self.is_hw1(device.product_key)
        client = Ledger_Client_Legacy(self, hid_dongle, ishw1)
        client.handler = handler
        return client

    def setup_device(self, device_info, wizard):
        devmgr = self.device_manager()
        device_id = device_info.device.id_
        client = devmgr.client_by_id(device_id)
        if client is None:
            raise OSError(_('Device id not found or was changed'))
        client.handler = self.create_handler(wizard)
        client.get_xpub("m/44'/0'/0'", 'standard')  # BIP44 coin type 0

    def get_xpub(self, device_id, derivation, xtype, wizard):
        devmgr = self.device_manager()
        client = devmgr.client_by_id(device_id)
        client.handler = self.create_handler(wizard)
        client.checkDevice()
        xpub = client.get_xpub(derivation, xtype)
        return xpub

    def get_client(self, keystore, force_pair=True):
        devmgr = self.device_manager()
        handler = keystore.handler
        with devmgr.hid_lock:
            client = devmgr.client_for_keystore(self, handler, keystore, force_pair)
        if client is not None:
            client.checkDevice()
        return client

    def show_address(self, wallet, address):
        sequence = wallet.get_address_index(address)
        wallet.get_keystore().show_address(sequence)
