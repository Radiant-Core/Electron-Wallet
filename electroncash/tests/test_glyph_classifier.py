# Golden-vector tests for the Glyph scriptPubKey classifier.
#
# Ported from radiant-ledger-app/view-only-ui/fixtures/classifier-vectors.json
# (24 assertions across 13 scriptPubKey vectors + round-trip builders).
# Every vector must pass; the malformed cases must correctly classify as
# None so the wallet falls through to TYPE_SCRIPT and refuses to display
# fake outputs as spendable.
#
# Sources of truth for the byte templates:
#   - classifier.mjs (JS reference, tested in parallel)
#   - docs/solutions/integration-issues/radiant-glyph-ft-template-and-view-only-renderer.md
#   - Radiant-Core/Radiant-Node src/script/script.h and interpreter.cpp

import unittest

from .. import glyph


# -------- Fixtures (see JSON source for full provenance per vector) --------

VECTORS = [
    # (name, spk_hex, expected_kind, expected_pkh_hex_or_None, expected_ref_hex_or_None)

    # Plain P2PKH — classifier returns None (defers to the standard P2PKH path).
    ('plain_p2pkh_large_coin',
     '76a914800d0414e758f790a48ad0f2960d566ef56cd5bf88ac',
     None, None, None),

    # NFT singleton (63B) — Ledger-custodied FlipperHub mint.
    ('nft_singleton_63b_ledger_mint',
     'd808480623910ba219a0903afa9f10140c31c30f0529d51f860401cb79caf24ed0000000007576a914a9763e88160a63a3f03bf846268ed0fb8abd8b5588ac',
     glyph.GLYPH_NFT_SINGLETON,
     'a9763e88160a63a3f03bf846268ed0fb8abd8b55',
     '08480623910ba219a0903afa9f10140c31c30f0529d51f860401cb79caf24ed000000000'),

    # FT holder (75B) — dominant mainnet FT, 2290 samples in the 500-block scan.
    ('ft_holder_75b_262a4d95',
     '76a91432e092994ebdf8db0861b0e9208878c4221c472188acbdd08b87c3c771b1a9f5015a4f26bfd80979ed196b5366257a6f30929646dfd943a400000000dec0e9aa76e378e4a269e69d',
     glyph.GLYPH_FT_HOLDER,
     '32e092994ebdf8db0861b0e9208878c4221c4721',
     '8b87c3c771b1a9f5015a4f26bfd80979ed196b5366257a6f30929646dfd943a400000000'),

    # FT holder (75B) — different token, proves the template generalizes.
    ('ft_holder_75b_6ce2bdb5_vout0',
     '76a9146fdc2880d5afbefcdbc89b31850414beec7d56bd88acbdd04bbba9407337be1465de8182dd88f5fb82355dd94e6acb45b1bc5e6f826aee4c00000000dec0e9aa76e378e4a269e69d',
     glyph.GLYPH_FT_HOLDER,
     '6fdc2880d5afbefcdbc89b31850414beec7d56bd',
     '4bbba9407337be1465de8182dd88f5fb82355dd94e6acb45b1bc5e6f826aee4c00000000'),

    # FT holder (75B) — same token, different recipient pkh.
    ('ft_holder_75b_6ce2bdb5_vout1',
     '76a914a434fbfe62e6cda47168f0ce4db4edb3c1b808e988acbdd04bbba9407337be1465de8182dd88f5fb82355dd94e6acb45b1bc5e6f826aee4c00000000dec0e9aa76e378e4a269e69d',
     glyph.GLYPH_FT_HOLDER,
     'a434fbfe62e6cda47168f0ce4db4edb3c1b808e9',
     '4bbba9407337be1465de8182dd88f5fb82355dd94e6acb45b1bc5e6f826aee4c00000000'),

    # FT mint-authority control script (241B) — MUST NOT classify as spendable.
    # These are the FT supply-governing singletons. Wallets that display them
    # as spendable would invite users to destroy mint authority.
    ('ft_control_241b_negative',
     '043bd10000d88b87c3c771b1a9f5015a4f26bfd80979ed196b5366257a6f30929646dfd943a406000000d08b87c3c771b1a9f5015a4f26bfd80979ed196b5366257a6f30929646dfd943a400000000036889090350c3000874da40a70d74da00bd5175c0c855797ea8597959797ea87e5a7a7eaabc01147f77587f040000000088817600a269a269577ae500a069567ae600a06901d053797e0cdec0e9aa76e378e4a269e69d7eaa76e47b9d547a818b76537a9c537ade789181547ae6939d635279cd01d853797e016a7e886778de519d547854807ec0eb557f777e5379ec78885379eac0e9885379cc519d75686d7551',
     None, None, None),

    # OP_RETURN — classifier returns None (defers to existing OP_RETURN handling).
    ('op_return_short', '6a036d736709736e6b205b7236395d',
     None, None, None),

    # Malformed FT: right length + right prefix + right mid, WRONG tail.
    # Must not classify as FT — template match is exact.
    ('malformed_ft_wrong_tail',
     '76a91432e092994ebdf8db0861b0e9208878c4221c472188acbdd08b87c3c771b1a9f5015a4f26bfd80979ed196b5366257a6f30929646dfd943a400000000ffffffffffffffffffffffff',
     None, None, None),

    # Malformed NFT: byte at offset 37 is 0xff, should be OP_DROP (0x75).
    ('malformed_nft_wrong_drop_byte',
     'd8358f3f90a2d278d17bd10a0b93482e9ba30e2ccd23ad4eefec2b08ebf4d12de900000000ff76a914a434fbfe62e6cda47168f0ce4db4edb3c1b808e988ac',
     None, None, None),

    # Malformed FT: 74 bytes (one byte short of tail).
    ('malformed_ft_wrong_length',
     '76a91432e092994ebdf8db0861b0e9208878c4221c472188acbdd08b87c3c771b1a9f5015a4f26bfd80979ed196b5366257a6f30929646dfd943a400000000dec0e9aa76e378e4a269e6',
     None, None, None),

    # Empty script — classifier returns None.
    ('empty', '', None, None, None),

    # NFT with wrong terminator: 88ab instead of 88ac.
    ('negative_nft_wrong_terminator',
     'd808480623910ba219a0903afa9f10140c31c30f0529d51f860401cb79caf24ed0000000007576a914a9763e88160a63a3f03bf846268ed0fb8abd8b5588ab',
     None, None, None),

    # FT with wrong middle opcode: 88acbdd1 instead of 88acbdd0.
    ('negative_ft_wrong_mid_opcode',
     '76a91432e092994ebdf8db0861b0e9208878c4221c472188acbdd18b87c3c771b1a9f5015a4f26bfd80979ed196b5366257a6f30929646dfd943a400000000dec0e9aa76e378e4a269e69d',
     None, None, None),

    # FT with tail-byte-0 flipped (ee instead of de).
    ('negative_ft_truncated_epilogue',
     '76a91432e092994ebdf8db0861b0e9208878c4221c472188acbdd08b87c3c771b1a9f5015a4f26bfd80979ed196b5366257a6f30929646dfd943a400000000eec0e9aa76e378e4a269e69d',
     None, None, None),
]


class GlyphClassifierTests(unittest.TestCase):

    def test_golden_vectors(self):
        """Every vector (positive and negative) classifies as expected."""
        for name, spk_hex, exp_kind, exp_pkh, exp_ref in VECTORS:
            with self.subTest(name=name):
                script_bytes = bytes.fromhex(spk_hex) if spk_hex else b''
                result = glyph.classify_glyph_output(script_bytes)
                if exp_kind is None:
                    self.assertIsNone(
                        result,
                        f"{name}: expected no match, got {result!r}")
                else:
                    self.assertIsNotNone(
                        result, f"{name}: expected a match, got None")
                    kind, pkh, ref = result
                    self.assertEqual(
                        kind, exp_kind,
                        f"{name}: kind mismatch")
                    self.assertEqual(
                        pkh.hex(), exp_pkh,
                        f"{name}: pkh mismatch")
                    if exp_ref is not None:
                        self.assertEqual(
                            ref.hex(), exp_ref,
                            f"{name}: ref mismatch")

    def test_is_nft_singleton_direct(self):
        """is_nft_singleton returns True for the known NFT and False for
        every negative vector."""
        # Positive case
        nft_spk = bytes.fromhex(
            'd808480623910ba219a0903afa9f10140c31c30f0529d51f860401cb79caf24e'
            'd0000000007576a914a9763e88160a63a3f03bf846268ed0fb8abd8b5588ac')
        self.assertTrue(glyph.is_nft_singleton(nft_spk))

        # Negative: wrong length (62 bytes)
        self.assertFalse(glyph.is_nft_singleton(nft_spk[:62]))

        # Negative: wrong terminator
        self.assertFalse(glyph.is_nft_singleton(nft_spk[:-1] + b'\xab'))

        # Negative: empty
        self.assertFalse(glyph.is_nft_singleton(b''))

    def test_is_ft_holder_direct(self):
        """is_ft_holder returns True for the known FT and False for every
        malformed 75-byte lookalike."""
        ft_spk = bytes.fromhex(
            '76a91432e092994ebdf8db0861b0e9208878c4221c472188acbdd08b87c3c771'
            'b1a9f5015a4f26bfd80979ed196b5366257a6f30929646dfd943a40000000'
            '0dec0e9aa76e378e4a269e69d')
        self.assertTrue(glyph.is_ft_holder(ft_spk))

        # Negative: wrong length
        self.assertFalse(glyph.is_ft_holder(ft_spk[:74]))

        # Negative: tail flipped
        bad_tail = bytearray(ft_spk)
        bad_tail[63] = 0xee
        self.assertFalse(glyph.is_ft_holder(bytes(bad_tail)))

        # Negative: middle byte flipped (bd → be)
        bad_mid = bytearray(ft_spk)
        bad_mid[25] = 0xbe
        self.assertFalse(glyph.is_ft_holder(bytes(bad_mid)))

    def test_script_type_integration(self):
        """After wiring into get_address_from_output_script, NFT and FT
        outputs resolve to TYPE_ADDRESS with the correct P2PKH address —
        not TYPE_SCRIPT. This is what lets the wallet display, select,
        and sign Glyph UTXOs using the existing P2PKH code paths."""
        from .. import transaction
        from ..address import Address
        from ..bitcoin import TYPE_ADDRESS

        # FT holder
        ft_spk = bytes.fromhex(
            '76a91432e092994ebdf8db0861b0e9208878c4221c472188acbdd08b87c3c771'
            'b1a9f5015a4f26bfd80979ed196b5366257a6f30929646dfd943a400000000'
            'dec0e9aa76e378e4a269e69d')
        typ, addr = transaction.get_address_from_output_script(ft_spk)
        self.assertEqual(typ, TYPE_ADDRESS)
        expected_addr = Address.from_P2PKH_hash(
            bytes.fromhex('32e092994ebdf8db0861b0e9208878c4221c4721'))
        self.assertEqual(addr, expected_addr)

        # NFT singleton
        nft_spk = bytes.fromhex(
            'd808480623910ba219a0903afa9f10140c31c30f0529d51f860401cb79caf24e'
            'd0000000007576a914a9763e88160a63a3f03bf846268ed0fb8abd8b5588ac')
        typ, addr = transaction.get_address_from_output_script(nft_spk)
        self.assertEqual(typ, TYPE_ADDRESS)
        expected_addr = Address.from_P2PKH_hash(
            bytes.fromhex('a9763e88160a63a3f03bf846268ed0fb8abd8b55'))
        self.assertEqual(addr, expected_addr)


if __name__ == '__main__':
    unittest.main()
