import threading
from functools import partial

from PyQt5.QtWidgets import QInputDialog, QLineEdit, QVBoxLayout, QLabel

from electroncash.i18n import _
from electroncash.plugins import hook
from electroncash.wallet import Standard_Wallet
from .ledger import LedgerPlugin
from ..hw_wallet.qt import QtHandlerBase, QtPluginBase
from ..hw_wallet.plugin import only_hook_if_libraries_available
from electroncash_gui.qt.util import *

class Plugin(LedgerPlugin, QtPluginBase):
    icon_unpaired = ":icons/ledger_unpaired.png"
    icon_paired = ":icons/ledger.png"

    def create_handler(self, window):
        return Ledger_Handler(window)

    @hook
    @only_hook_if_libraries_available
    def receive_menu(self, menu, addrs, wallet):
        if len(addrs) != 1:
            return
        keystore = wallet.get_keystore()
        if not isinstance(keystore, self.keystore_class):
            return
        def show_address():
            keystore.thread.add(partial(self.show_address, wallet, addrs[0]))
        menu.addAction(_("Show on Ledger"), show_address)

class Ledger_Handler(QtHandlerBase):
    setup_signal = pyqtSignal()
    auth_signal = pyqtSignal(object)

    def __init__(self, win):
        super(Ledger_Handler, self).__init__(win, 'Ledger')
        self.setup_signal.connect(self.setup_dialog)
        self.auth_signal.connect(self.auth_dialog)

    def word_dialog(self, msg):
        response = QInputDialog.getText(self.top_level_window(), "Ledger Wallet Authentication", msg, QLineEdit.Password)
        if not response[1]:
            self.word = None
        else:
            self.word = str(response[0])
        self.done.set()
    
    def message_dialog(self, msg, on_cancel=None):
        self.clear_dialog()
        title = _("Please check your {} device").format(self.device)
        self.dialog = dialog = WindowModalDialog(self.top_level_window(), title)
        l = QLabel(msg)
        vbox = QVBoxLayout(dialog)
        vbox.addWidget(l)
        if on_cancel:
            dialog.rejected.connect(on_cancel)
            vbox.addLayout(Buttons(CancelButton(dialog)))
        dialog.show()

    def auth_dialog(self, data):
        try:
            from .auth2fa import LedgerAuthDialog
        except ImportError as e:
            self.message_dialog(str(e))
            return
        dialog = LedgerAuthDialog(self, data)
        dialog.exec_()
        self.word = dialog.pin
        self.done.set()
                    
    def get_auth(self, data):
        self.done.clear()
        self.auth_signal.emit(data)
        self.done.wait()
        return self.word
        
    def get_setup(self):
        self.done.clear()
        self.setup_signal.emit()
        self.done.wait()
        return 
        
    def setup_dialog(self):
        from electroncash_gui.qt.util import WindowModalDialog
        from PyQt5.QtWidgets import QVBoxLayout, QLabel, QPushButton
        dialog = WindowModalDialog(self.top_level_window(), _('Ledger Setup'))
        vbox = QVBoxLayout(dialog)
        vbox.addWidget(QLabel(
            _('Please open the Bitcoin app on your Ledger device, then close this dialog.\n\n'
              'Supported: Ledger Bitcoin app v1.x (Nano S) and v2.x+ (Nano X, Nano S Plus, Stax, Flex).')
        ))
        btn = QPushButton(_('Done'))
        btn.clicked.connect(dialog.accept)
        vbox.addWidget(btn)
        dialog.exec_()
        self.done.set()


        
        
        
        
