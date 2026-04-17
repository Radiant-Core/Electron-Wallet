from electroncash.i18n import _

fullname = _('Ledger Wallet')
description = _('Provides support for Ledger hardware wallet. Open the Bitcoin Cash app on your Ledger device for proper SIGHASH_FORKID support (recommended). Bitcoin app v2.1+ has signing issues; BCH app provides native fork ID compatibility. BIP44 derivation m/44\'/0\'/0\'. Supports app v1.x legacy (btchip) and v2.1+ modern PSBT protocol.')
requires = [('ledger_bitcoin', 'github.com/LedgerHQ/app-bitcoin-new')]
registers_keystore = ('hardware', 'ledger', _("Ledger wallet"))
available_for = ['qt', 'cmdline']
