# Glyph Token Awareness for Electron Radiant
#
# This module provides detection of Radiant reference-prefixed scripts
# (used by Glyph tokens) to prevent accidental spending/destruction of
# tokens. It does NOT provide full Glyph protocol support — only
# protective awareness.
#
# Radiant reference opcodes:
#   OP_PUSHINPUTREF     (0xd0) + 36 bytes  — push a UTXO reference
#   OP_REQUIREINPUTREF  (0xd8) + 36 bytes  — require a reference in inputs
#   OP_DISALLOWPUSHINPUTREF         (0xd1) — disallow push ref
#   OP_DISALLOWPUSHINPUTREFSIBLING  (0xd2) — disallow sibling push ref
#
# A typical Glyph token output script:
#   d0 <36-byte ref> 75 76a914 <20-byte hash> 88ac
#   ^-- ref prefix --^ ^---- standard P2PKH -----^

from .util import PrintError

# Radiant-specific opcodes for UTXO references
OP_PUSHINPUTREF = 0xd0
OP_DISALLOWPUSHINPUTREF = 0xd1
OP_DISALLOWPUSHINPUTREFSIBLING = 0xd2
OP_REQUIREINPUTREF = 0xd8
OP_DROP = 0x75

# Reference data size: 32-byte txid + 4-byte output index
REF_DATA_SIZE = 36

# Opcodes that take a 36-byte reference argument
_REF_OPCODES = frozenset((OP_PUSHINPUTREF, OP_REQUIREINPUTREF))

# Opcodes that are single-byte Radiant markers (no data)
_REF_MARKER_OPCODES = frozenset((OP_DISALLOWPUSHINPUTREF, OP_DISALLOWPUSHINPUTREFSIBLING))


def has_radiant_refs(script_bytes):
    """Returns True if the script begins with Radiant reference opcodes
    (OP_PUSHINPUTREF or OP_REQUIREINPUTREF). This indicates the output
    likely carries a Glyph token."""
    if not script_bytes or len(script_bytes) < 1:
        return False
    return script_bytes[0] in _REF_OPCODES


def strip_radiant_refs(script_bytes):
    """Strip all leading Radiant reference prefixes from a script and return
    the inner (standard) locking script.

    Handles patterns like:
        d0 <36 bytes> 75 [d8 <36 bytes> 75] ... <standard_script>

    Returns the inner script bytes, or None if the script doesn't start
    with reference opcodes or is malformed. Also returns None if stripping
    would result in an empty script."""
    if not script_bytes or len(script_bytes) < 1:
        return None

    pos = 0
    found_ref = False

    while pos < len(script_bytes):
        op = script_bytes[pos]

        if op in _REF_OPCODES:
            # Need at least 1 (opcode) + 36 (ref data) bytes
            if pos + 1 + REF_DATA_SIZE > len(script_bytes):
                return None  # malformed
            pos += 1 + REF_DATA_SIZE
            found_ref = True

            # Optionally consume OP_DROP after the reference
            if pos < len(script_bytes) and script_bytes[pos] == OP_DROP:
                pos += 1

        elif op in _REF_MARKER_OPCODES:
            # Single-byte markers, skip them
            pos += 1
            found_ref = True

        else:
            # Not a reference opcode — remainder is the inner script
            break

    if not found_ref:
        return None

    inner = script_bytes[pos:]
    if not inner:
        return None

    return bytes(inner)


def extract_ref_id(script_bytes):
    """Extract the first reference ID (36 bytes) from a reference-prefixed
    script. Returns the raw 36-byte reference or None."""
    if not script_bytes or len(script_bytes) < 1 + REF_DATA_SIZE:
        return None
    if script_bytes[0] not in _REF_OPCODES:
        return None
    return bytes(script_bytes[1:1 + REF_DATA_SIZE])


class WalletData(PrintError):
    """Tracks Glyph reference UTXOs in the wallet to prevent accidental
    spending. Mirrors the pattern used by slp.WalletData but much simpler
    since we only need to track which UTXOs have references, not parse
    full token semantics."""

    def __init__(self, wallet):
        self.wallet = wallet
        # Set of txo strings ("txid:n") that have Radiant reference scripts
        self.ref_txos = set()
        # Maps txo string → first reference ID bytes (for display)
        self.ref_ids = {}
        self.need_rebuild = False

    def diagnostic_name(self):
        return f'{type(self).__name__}/{self.wallet.diagnostic_name()}'

    def clear(self):
        self.ref_txos.clear()
        self.ref_ids.clear()

    def is_glyph_ref(self, txo):
        """Returns True if the given txo (string 'txid:n') is a Glyph
        reference UTXO that should not be spent."""
        return txo in self.ref_txos

    def ref_info_for_txo(self, txo):
        """Returns the reference ID hex for the given txo, or None."""
        ref_id = self.ref_ids.get(txo)
        if ref_id is not None:
            return ref_id.hex()
        return None

    def add_tx(self, tx_hash, tx):
        """Scan a transaction for Glyph reference outputs and track them.
        Called by wallet.add_transaction with lock held."""
        for n, (typ, addr, value) in enumerate(tx.outputs()):
            raw_script = tx.output_script(n)
            if raw_script and has_radiant_refs(raw_script):
                txo = f"{tx_hash}:{n}"
                self.ref_txos.add(txo)
                ref_id = extract_ref_id(raw_script)
                if ref_id is not None:
                    self.ref_ids[txo] = ref_id

    def rm_tx(self, tx_hash):
        """Remove tracking for a transaction. Called by
        wallet.remove_transaction with lock held."""
        to_remove = [txo for txo in self.ref_txos
                     if txo.rsplit(':', 1)[0] == tx_hash]
        for txo in to_remove:
            self.ref_txos.discard(txo)
            self.ref_ids.pop(txo, None)

    def load(self):
        """Load persisted glyph data from wallet storage."""
        data = self.wallet.storage.get('glyph_ref_txos')
        if isinstance(data, list):
            self.ref_txos = set(data)
        data = self.wallet.storage.get('glyph_ref_ids')
        if isinstance(data, dict):
            self.ref_ids = {k: bytes.fromhex(v) for k, v in data.items()
                           if isinstance(v, str)}
        else:
            self.need_rebuild = True

    def save(self):
        """Persist glyph data to wallet storage."""
        self.wallet.storage.put('glyph_ref_txos', list(self.ref_txos))
        self.wallet.storage.put('glyph_ref_ids',
                                {k: v.hex() for k, v in self.ref_ids.items()})

    def rebuild(self):
        """Rebuild glyph data from wallet transactions."""
        self.clear()
        for tx_hash, tx in self.wallet.transactions.items():
            self.add_tx(tx_hash, tx)
        self.need_rebuild = False
