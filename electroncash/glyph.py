# Glyph Token Awareness for Electron Radiant
#
# This module provides detection of Radiant reference-prefixed scripts
# (used by Glyph tokens) to prevent accidental spending/destruction of
# tokens. It does NOT provide full Glyph protocol support — only
# protective awareness.
#
# Radiant reference opcodes (verified against Radiant-Core/Radiant-Node
# src/script/script.h):
#   OP_PUSHINPUTREF              (0xd0) + 36 bytes — FT-style push ref
#   OP_REQUIREINPUTREF           (0xd1) + 36 bytes — require ref present
#   OP_DISALLOWPUSHINPUTREF      (0xd2) — disallow push ref
#   OP_PUSHINPUTREFSINGLETON     (0xd8) + 36 bytes — NFT singleton push ref
#   OP_STATESEPARATOR            (0xbd) — runtime NOP separating
#                                         P2PKH prologue from FT epilogue
#
# Three on-chain shapes recognized by this module (from a 2309-sample
# mainnet scan across 6 distinct tokens, 500 blocks):
#
#   Plain P2PKH (25B):   76a914 <pkh:20> 88ac
#   NFT singleton (63B): d8 <ref:36> 75 76a914 <pkh:20> 88ac
#   FT holder    (75B):  76a914 <pkh:20> 88ac bd d0 <ref:36>
#                        dec0e9aa76e378e4a269e69d
#
# The FT epilogue's trailing 12 bytes implement Σ-in ≥ Σ-out conservation
# via OP_CODESCRIPTHASHVALUESUM_UTXOS / _OUTPUTS. Spending an FT holder
# requires the same scriptSig as plain P2PKH: <sig> <pubkey>.

from .util import PrintError

# Radiant-specific opcodes for UTXO references
OP_PUSHINPUTREF = 0xd0
OP_REQUIREINPUTREF = 0xd1
OP_DISALLOWPUSHINPUTREF = 0xd2
OP_PUSHINPUTREFSINGLETON = 0xd8
OP_STATESEPARATOR = 0xbd
OP_DROP = 0x75

# Reference data size: 32-byte txid + 4-byte output index
REF_DATA_SIZE = 36

# Opcodes that take a 36-byte reference argument. Includes both OP_PUSHINPUTREF
# (0xd0, used by FTs) and OP_PUSHINPUTREFSINGLETON (0xd8, used by NFTs).
_REF_OPCODES = frozenset((OP_PUSHINPUTREF, OP_PUSHINPUTREFSINGLETON))

# Opcodes that are single-byte Radiant markers (no data).
_REF_MARKER_OPCODES = frozenset((OP_DISALLOWPUSHINPUTREF,))

# Byte constants for the 75-byte FT holder shape.
# Layout: 76a914 <pkh:20> 88ac bd d0 <ref:36> <FT_TAIL_BYTES>
_FT_MID_BYTES = bytes.fromhex('88acbdd0')       # 88ac ends P2PKH; bd=STATESEPARATOR; d0=PUSHINPUTREF
_FT_TAIL_BYTES = bytes.fromhex('dec0e9aa76e378e4a269e69d')
FT_HOLDER_LEN = 75
NFT_SINGLETON_LEN = 63

# Script-type classification returned by classify_glyph_output().
GLYPH_NONE = None       # plain output — defer to normal recognizer
GLYPH_NFT_SINGLETON = 'nft_singleton'
GLYPH_FT_HOLDER = 'ft_holder'


def has_radiant_refs(script_bytes):
    """Returns True if the script begins with Radiant reference opcodes
    (OP_PUSHINPUTREF 0xd0 or OP_PUSHINPUTREFSINGLETON 0xd8). This
    indicates the output likely carries a Glyph token.

    Note: OP_REQUIREINPUTREF (0xd1) is deliberately NOT checked here — it
    is used in spend-time constraint scripts, not in output-side ref
    prefixes. The _REF_OPCODES frozenset is authoritative; this docstring
    is documentation only.
    """
    if not script_bytes:
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
    if not script_bytes:
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


class GlyphOutput:
    """Base class for typed Glyph output wrappers.

    Glyph token outputs (FT, NFT) are TYPE_SCRIPT in Electron Cash because
    their scriptPubKey is a reference-prefixed P2PKH — not a bare address and
    not an OP_RETURN.  Code that classifies TYPE_SCRIPT outputs (e.g. the
    Ledger signing plugin) must distinguish them from genuine OP_RETURN data
    outputs to avoid running OP_RETURN validation against them.

    Usage::

        from electroncash.glyph import GlyphFTOutput, GlyphNFTOutput
        if isinstance(address, (GlyphFTOutput, GlyphNFTOutput)):
            # skip OP_RETURN validator; firmware handles these natively
    """

    __slots__ = ('script_bytes', 'ref_id')

    def __init__(self, script_bytes: bytes):
        self.script_bytes = script_bytes
        self.ref_id = extract_ref_id(script_bytes)

    def __repr__(self):
        ref_hex = self.ref_id.hex() if self.ref_id else 'unknown'
        return f'<{type(self).__name__} ref={ref_hex[:16]}…>'

    def to_script_hex(self) -> str:
        return self.script_bytes.hex()


class GlyphFTOutput(GlyphOutput):
    """Typed wrapper for a Glyph fungible-token (FT) output.

    FT outputs carry a d0+36B OP_PUSHINPUTREF prefix followed by a standard
    P2PKH script.  The ref is the token type identifier (the 36-byte tokenRef).
    """


class GlyphNFTOutput(GlyphOutput):
    """Typed wrapper for a Glyph non-fungible-token (NFT) / singleton output.

    NFT singleton outputs carry a d8+36B OP_REQUIREINPUTREF prefix (or a
    d0+36B prefix for mint-authority scripts) followed by a standard P2PKH.
    The ref is the unique token identity.
    """


def classify_glyph_output(script_bytes: bytes):
    """Return a GlyphFTOutput, GlyphNFTOutput, or None for the given script.

    Classification heuristic:
    - Starts with OP_PUSHINPUTREF (0xd0)  → GlyphFTOutput
    - Starts with OP_REQUIREINPUTREF (0xd8) → GlyphNFTOutput
    - Otherwise → None (not a Glyph output, or malformed)
    """
    if not script_bytes or len(script_bytes) < 1 + REF_DATA_SIZE:
        return None
    opcode = script_bytes[0]
    if opcode == OP_PUSHINPUTREF:
        return GlyphFTOutput(script_bytes)
    if opcode == OP_REQUIREINPUTREF:
        return GlyphNFTOutput(script_bytes)
    return None


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
        Called by wallet.add_transaction with lock held.

        Handles two shapes:
          1. Ref-prefixed scripts (NFT singletons + older ref-prefix variants)
             detected via has_radiant_refs() at the start of the script.
          2. FT holders (75B, P2PKH prologue + glyph epilogue) — these do
             NOT start with a ref opcode. classify_glyph_output() exact-
             matches the 75-byte template and returns the embedded ref.
        """
        for n, (typ, addr, value) in enumerate(tx.outputs()):
            raw_script = tx.output_script(n)
            if not raw_script:
                continue
            # Precise classifier first: covers NFT singletons (63B) and
            # FT holders (75B). Returns the canonical 36-byte ref for
            # balance grouping.
            gm = classify_glyph_output(raw_script)
            if gm is not None:
                _kind, _pkh, ref_bytes = gm
                txo = f"{tx_hash}:{n}"
                self.ref_txos.add(txo)
                if ref_bytes is not None:
                    self.ref_ids[txo] = ref_bytes
                continue
            # Fall back to loose prefix detection for shapes the precise
            # classifier doesn't recognize (241B FT control, dMint, etc).
            if has_radiant_refs(raw_script):
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


# ---------------------------------------------------------------------------
# Precise shape classifier — added 2026-04.
#
# Recognizes the three mainnet-observed spendable shapes with exact byte
# matching (not just prefix detection). Backed by 24 golden vectors in
# tests/test_glyph_classifier.py. The port target from the JavaScript
# reference is radiant-ledger-app/view-only-ui/classifier.mjs.
# ---------------------------------------------------------------------------

def _is_plain_p2pkh(b):
    return (len(b) == 25
            and b[0] == 0x76 and b[1] == 0xa9 and b[2] == 0x14
            and b[23] == 0x88 and b[24] == 0xac)


def is_nft_singleton(script_bytes):
    """Exact 63-byte NFT singleton shape: d8 <ref:36> 75 76a914 <pkh:20> 88ac.

    A match is a strong indicator of a Glyph NFT; the 36-byte ref uniquely
    identifies the mint. Returns True only on an exact shape match — does
    NOT accept any 63-byte d8-prefixed script."""
    b = script_bytes
    if not b or len(b) != NFT_SINGLETON_LEN:
        return False
    return (b[0] == OP_PUSHINPUTREFSINGLETON
            and b[37] == OP_DROP
            and b[38] == 0x76 and b[39] == 0xa9 and b[40] == 0x14
            and b[61] == 0x88 and b[62] == 0xac)


def is_ft_holder(script_bytes):
    """Exact 75-byte FT holder shape: 76a914 <pkh:20> 88ac bd d0 <ref:36>
    <FT_TAIL 12B>.

    The FT epilogue enforces photon-value conservation at consensus (Σ
    inputs >= Σ outputs per codeScriptHash). The prologue is standard
    P2PKH, so the spend scriptSig is <sig> <pubkey> — same as a plain
    P2PKH. The epilogue bytes are invariant across every FT token
    observed on mainnet (2309 samples, 6 tokens)."""
    b = script_bytes
    if not b or len(b) != FT_HOLDER_LEN:
        return False
    # First 25 bytes must be a well-formed P2PKH prologue:
    # 76a914 <pkh:20> 88ac — reuse the helper to avoid drifting the
    # pattern from the plain-P2PKH recognizer.
    if not _is_plain_p2pkh(b[0:25]):
        return False
    if b[25] != OP_STATESEPARATOR or b[26] != OP_PUSHINPUTREF:
        return False
    if b[63:] != _FT_TAIL_BYTES:
        return False
    return True


def classify_glyph_output(script_bytes):
    """Return (kind, pkh_bytes, ref_bytes_or_none) for a recognized Glyph
    shape, or None if not a recognized Glyph output.

    kind is GLYPH_NFT_SINGLETON or GLYPH_FT_HOLDER.
    pkh_bytes is the 20-byte pubkey hash (same as a standard P2PKH would
    extract) — this is the owning address of the output.
    ref_bytes is the 36-byte token identifier (None only if the output
    doesn't carry a ref, which shouldn't happen for the two recognized
    kinds but keeps the return shape uniform).

    Exact byte matches only. Malformed or near-miss shapes return None
    (callers should fall through to TYPE_SCRIPT / unknown).

    IMPORTANT — classifier-vs-consensus gap. A match indicates the output
    *has the shape of* a spendable Glyph UTXO. It does NOT guarantee that
    a spend will succeed at consensus. Spending a Glyph UTXO requires the
    spending transaction to (a) present a valid P2PKH scriptSig for the
    prologue, AND (b) satisfy the protocol's input-ref and conservation
    constraints on the spending tx as a whole. An attacker can mint a
    75-byte output with a ref that was never minted — the wallet will
    display it and mark it "spendable," but broadcast will fail consensus.
    Callers that surface these outputs as spendable balance should
    document this to the user, not treat a classifier match as proof of
    spendability."""
    if is_nft_singleton(script_bytes):
        return (GLYPH_NFT_SINGLETON,
                bytes(script_bytes[41:61]),
                bytes(script_bytes[1:37]))
    if is_ft_holder(script_bytes):
        return (GLYPH_FT_HOLDER,
                bytes(script_bytes[3:23]),
                bytes(script_bytes[27:63]))
    return None
