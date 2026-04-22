"""Tests for electroncash.glyph — typed output classes and detection utilities."""
import unittest

from ..glyph import (
    OP_PUSHINPUTREF,
    OP_REQUIREINPUTREF,
    OP_DROP,
    REF_DATA_SIZE,
    has_radiant_refs,
    strip_radiant_refs,
    extract_ref_id,
    classify_glyph_output,
    GlyphOutput,
    GlyphFTOutput,
    GlyphNFTOutput,
    WalletData,
)

# --- Test vectors -----------------------------------------------------------

# A 36-byte reference (all-zero for simplicity)
ZERO_REF = bytes(REF_DATA_SIZE)

# Minimal P2PKH suffix: OP_DUP OP_HASH160 <20B> OP_EQUALVERIFY OP_CHECKSIG
_P2PKH_SUFFIX = bytes([0x76, 0xa9, 0x14]) + bytes(20) + bytes([0x88, 0xac])

def _ft_script(ref=ZERO_REF):
    """d0 <36B ref> 75 <P2PKH>  — standard Glyph FT output script."""
    return bytes([OP_PUSHINPUTREF]) + ref + bytes([OP_DROP]) + _P2PKH_SUFFIX

def _nft_script(ref=ZERO_REF):
    """d8 <36B ref> 75 <P2PKH>  — standard Glyph NFT / singleton script."""
    return bytes([OP_REQUIREINPUTREF]) + ref + bytes([OP_DROP]) + _P2PKH_SUFFIX

def _bare_p2pkh():
    """Standard P2PKH with no Glyph prefix."""
    return _P2PKH_SUFFIX

def _op_return_script():
    """Minimal OP_RETURN data script."""
    return bytes([0x6a, 0x04]) + b'TEST'


# ---------------------------------------------------------------------------
# has_radiant_refs
# ---------------------------------------------------------------------------

class TestHasRadiantRefs(unittest.TestCase):

    def test_ft_script_detected(self):
        self.assertTrue(has_radiant_refs(_ft_script()))

    def test_nft_script_detected(self):
        self.assertTrue(has_radiant_refs(_nft_script()))

    def test_bare_p2pkh_not_detected(self):
        self.assertFalse(has_radiant_refs(_bare_p2pkh()))

    def test_op_return_not_detected(self):
        self.assertFalse(has_radiant_refs(_op_return_script()))

    def test_empty_bytes_not_detected(self):
        self.assertFalse(has_radiant_refs(b''))

    def test_none_not_detected(self):
        self.assertFalse(has_radiant_refs(None))


# ---------------------------------------------------------------------------
# strip_radiant_refs
# ---------------------------------------------------------------------------

class TestStripRadiantRefs(unittest.TestCase):

    def test_ft_strips_to_p2pkh(self):
        inner = strip_radiant_refs(_ft_script())
        self.assertIsNotNone(inner)
        self.assertEqual(inner, _P2PKH_SUFFIX)

    def test_nft_strips_to_p2pkh(self):
        inner = strip_radiant_refs(_nft_script())
        self.assertIsNotNone(inner)
        self.assertEqual(inner, _P2PKH_SUFFIX)

    def test_bare_p2pkh_returns_none(self):
        self.assertIsNone(strip_radiant_refs(_bare_p2pkh()))

    def test_malformed_truncated_ref_returns_none(self):
        # ref data cut short (only 10 bytes)
        bad = bytes([OP_PUSHINPUTREF]) + bytes(10)
        self.assertIsNone(strip_radiant_refs(bad))

    def test_empty_returns_none(self):
        self.assertIsNone(strip_radiant_refs(b''))


# ---------------------------------------------------------------------------
# extract_ref_id
# ---------------------------------------------------------------------------

class TestExtractRefId(unittest.TestCase):

    def _distinct_ref(self):
        return bytes(range(REF_DATA_SIZE))

    def test_ft_ref_extracted(self):
        ref = self._distinct_ref()
        result = extract_ref_id(_ft_script(ref))
        self.assertEqual(result, ref)

    def test_nft_ref_extracted(self):
        ref = self._distinct_ref()
        result = extract_ref_id(_nft_script(ref))
        self.assertEqual(result, ref)

    def test_bare_p2pkh_returns_none(self):
        self.assertIsNone(extract_ref_id(_bare_p2pkh()))

    def test_too_short_returns_none(self):
        self.assertIsNone(extract_ref_id(bytes([OP_PUSHINPUTREF]) + bytes(10)))


# ---------------------------------------------------------------------------
# classify_glyph_output — the new typed-class API
# ---------------------------------------------------------------------------

class TestClassifyGlyphOutput(unittest.TestCase):

    def test_ft_script_returns_glyph_ft_output(self):
        result = classify_glyph_output(_ft_script())
        self.assertIsInstance(result, GlyphFTOutput)

    def test_nft_script_returns_glyph_nft_output(self):
        result = classify_glyph_output(_nft_script())
        self.assertIsInstance(result, GlyphNFTOutput)

    def test_ft_is_subclass_of_glyph_output(self):
        result = classify_glyph_output(_ft_script())
        self.assertIsInstance(result, GlyphOutput)

    def test_nft_is_subclass_of_glyph_output(self):
        result = classify_glyph_output(_nft_script())
        self.assertIsInstance(result, GlyphOutput)

    def test_bare_p2pkh_returns_none(self):
        self.assertIsNone(classify_glyph_output(_bare_p2pkh()))

    def test_op_return_returns_none(self):
        self.assertIsNone(classify_glyph_output(_op_return_script()))

    def test_empty_returns_none(self):
        self.assertIsNone(classify_glyph_output(b''))

    def test_too_short_returns_none(self):
        self.assertIsNone(classify_glyph_output(bytes([OP_PUSHINPUTREF]) + bytes(5)))

    def test_ref_id_stored_on_ft_output(self):
        ref = bytes(range(REF_DATA_SIZE))
        result = classify_glyph_output(_ft_script(ref))
        self.assertEqual(result.ref_id, ref)

    def test_ref_id_stored_on_nft_output(self):
        ref = bytes(range(REF_DATA_SIZE))
        result = classify_glyph_output(_nft_script(ref))
        self.assertEqual(result.ref_id, ref)

    def test_script_bytes_stored(self):
        script = _ft_script()
        result = classify_glyph_output(script)
        self.assertEqual(result.script_bytes, script)

    def test_to_script_hex(self):
        script = _ft_script()
        result = classify_glyph_output(script)
        self.assertEqual(result.to_script_hex(), script.hex())

    def test_repr_contains_class_name(self):
        ft = classify_glyph_output(_ft_script())
        self.assertIn('GlyphFTOutput', repr(ft))
        nft = classify_glyph_output(_nft_script())
        self.assertIn('GlyphNFTOutput', repr(nft))


# ---------------------------------------------------------------------------
# isinstance guard — exactly what the Ledger signing path uses
# ---------------------------------------------------------------------------

class TestIsInstanceGuard(unittest.TestCase):
    """Verify that the isinstance() check used in the Ledger signing bypass
    correctly gates on GlyphFTOutput and GlyphNFTOutput but not on other
    TYPE_SCRIPT objects."""

    def _is_glyph(self, obj):
        return isinstance(obj, (GlyphFTOutput, GlyphNFTOutput))

    def test_ft_output_is_glyph(self):
        obj = classify_glyph_output(_ft_script())
        self.assertTrue(self._is_glyph(obj))

    def test_nft_output_is_glyph(self):
        obj = classify_glyph_output(_nft_script())
        self.assertTrue(self._is_glyph(obj))

    def test_none_is_not_glyph(self):
        self.assertFalse(self._is_glyph(None))

    def test_string_address_is_not_glyph(self):
        self.assertFalse(self._is_glyph("1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf"))

    def test_plain_bytes_is_not_glyph(self):
        self.assertFalse(self._is_glyph(_ft_script()))  # raw bytes, not wrapped


if __name__ == '__main__':
    unittest.main()
