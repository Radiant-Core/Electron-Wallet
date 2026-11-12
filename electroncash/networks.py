# Electron Cash - lightweight Bitcoin Cash client
# Copyright (C) 2011 thomasv@gitorious
# Copyright (C) 2017 Neil Booth
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import json
import pkgutil

from .asert_daa import ASERTDaa, Anchor

def _read_json_dict(filename):
    try:
        data = pkgutil.get_data(__name__, filename)
        r = json.loads(data.decode('utf-8'))
    except:
        r = {}
    return r

class AbstractNet:
    TESTNET = False
    LEGACY_POW_TARGET_TIMESPAN = 14 * 24 * 60 * 60   # 2 weeks
    LEGACY_POW_TARGET_INTERVAL = 10 * 60  # 10 minutes
    LEGACY_POW_RETARGET_BLOCKS = LEGACY_POW_TARGET_TIMESPAN // LEGACY_POW_TARGET_INTERVAL  # 2016 blocks
    BASE_UNITS = {'RXD': 8, 'mRXD': 5, 'photons': 0}
    DEFAULT_UNIT = "RXD"


class MainNet(AbstractNet):
    TESTNET = False
    WIF_PREFIX = 0x80
    ADDRTYPE_P2PKH = 0
    ADDRTYPE_P2SH = 5
    CASHADDR_PREFIX = "radaddr"
    RPA_PREFIX = "paycode"
    GENESIS = "0000000065d8ed5d8be28d6876b3ffb660ac2a6c0ca59e437e1f7a6f4e003fb4"
    DEFAULT_PORTS = {'t': '50010', 's': '50012'}
    DEFAULT_SERVERS = _read_json_dict('servers.json')  # DO NOT MODIFY IN CLIENT CODE
    TITLE = 'Electron Radiant'

    # Chain checkpoint: a header batch containing this height must carry this
    # exact block hash, or the chain is rejected (guards against wrong-chain
    # servers). Anchored at the Radiant SecurityUpgrade activation block
    # (chainparams.cpp SecurityUpgradeHeight). Update to a recent height when
    # cutting a new release.
    CHECKPOINT_BLOCK_HEIGHT = 440000
    CHECKPOINT_BLOCK_HASH = "000000000000003a98a037202d92e71981aba4ab80a80b9b407a377a36059e0f"

    # Note: this is not the Merkle root of the verification block itself , but a Merkle root of
    # all blockchain headers up until and including this block. To get this value you need to
    # connect to an ElectrumX server you trust and issue it a protocol command. This can be
    # done in the console as follows:
    #
    #    network.synchronous_get(("blockchain.block.header", [height, height]))
    #
    # Consult the ElectrumX documentation for more details.
    VERIFICATION_BLOCK_MERKLE_ROOT = "6cafe6844c6f42085778412ce6415e810cbfb030a505ba9731e29bde72097421"
    VERIFICATION_BLOCK_HEIGHT = 18144
    asert_daa = ASERTDaa(is_testnet=False)
    # Note: We *must* specify the anchor if the checkpoint is after the anchor, due to the way
    # blockchain.py skips headers after the checkpoint.  So all instances that have a checkpoint
    # after the anchor must specify the anchor as well.
    asert_daa.anchor = Anchor(height=18206, bits=453224288, prev_time=1657404650)
    # V2 anchor: block 409999 (one before ASERT_HALF_LIFE_UPGRADE_HEIGHT=410000)
    # bits=0x1a008d39, prev_time=1773088826 (timestamp of block 409998)
    asert_daa.anchor_v2 = Anchor(height=409999, bits=0x1a008d39, prev_time=1773088826)

    # Version numbers for BIP32 extended keys
    # standard: xprv, xpub
    XPRV_HEADERS = {
        'standard': 0x0488ade4,
    }

    XPUB_HEADERS = {
        'standard': 0x0488b21e,
    }


class TestNet(AbstractNet):
    TESTNET = True
    WIF_PREFIX = 0xef
    ADDRTYPE_P2PKH = 111
    ADDRTYPE_P2SH = 196
    CASHADDR_PREFIX = "radtest"
    RPA_PREFIX = "paycodetest"
    GENESIS = "000000000d8ada264d16f87a590b2af320cd3c7e3f9be5482163e830fd00aca2"
    DEFAULT_PORTS = {'t':'51010', 's':'51012'}
    DEFAULT_SERVERS = _read_json_dict('servers_testnet.json')  # DO NOT MODIFY IN CLIENT CODE
    TITLE = 'Electron Radiant Testnet'
    BASE_UNITS = {'tRXD': 8, 'mtRXD': 5, 'tbits': 2}
    DEFAULT_UNIT = "tRXD"

    # No trusted checkpoint anchor for the Radiant testnet yet; the check is
    # skipped while the height is None.
    CHECKPOINT_BLOCK_HEIGHT = None
    CHECKPOINT_BLOCK_HASH = None

    VERIFICATION_BLOCK_MERKLE_ROOT = None  # TODO: pin a trusted root; the BCH-inherited value was removed
    VERIFICATION_BLOCK_HEIGHT = 32000
    asert_daa = ASERTDaa(is_testnet=True)
    asert_daa.anchor = Anchor(height=33000, bits=453224288, prev_time=1657404650)

    # Version numbers for BIP32 extended keys
    # standard: tprv, tpub
    XPRV_HEADERS = {
        'standard': 0x04358394,
    }

    XPUB_HEADERS = {
        'standard': 0x043587cf,
    }


class ScaleNet(TestNet):
    GENESIS = "00000000ea7340a6e9ae28ad8ca95a652c8da00ee7ea97e6cb42cd1558884c87"
    TITLE = 'Electron Radiant Scalenet'
    BASE_UNITS = {'sRXD': 8, 'msRXD': 5, 'sbits': 2}
    DEFAULT_UNIT = "tRXD"


    DEFAULT_SERVERS = _read_json_dict('servers_scalenet.json')  # DO NOT MODIFY IN CLIENT CODE
    DEFAULT_PORTS = {'t': '63001', 's': '63002'}

    CHECKPOINT_BLOCK_HEIGHT = None
    CHECKPOINT_BLOCK_HASH = None

    VERIFICATION_BLOCK_MERKLE_ROOT = None
    VERIFICATION_BLOCK_HEIGHT = 2016
    asert_daa = ASERTDaa(is_testnet=False)  # Despite being a "testnet", ScaleNet uses 2d half-life
    asert_daa.anchor = None  # Intentionally not specified because it's after checkpoint; blockchain.py will calculate


# All new code should access this to get the current network config.
net = MainNet


def _set_units():
    from . import util
    util.base_units = net.BASE_UNITS.copy()
    util.DEFAULT_BASE_UNIT = net.DEFAULT_UNIT
    util.recalc_base_units()


def set_mainnet():
    global net
    net = MainNet
    _set_units()


def set_testnet():
    global net
    net = TestNet
    _set_units()


def set_scalenet():
    global net
    net = ScaleNet
    _set_units()


# Compatibility
def _instancer(cls):
    return cls()


@_instancer
class NetworkConstants:
    ''' Compatibility class for old code such as extant plugins.

    Client code can just do things like:
    NetworkConstants.ADDRTYPE_P2PKH, NetworkConstants.DEFAULT_PORTS, etc.

    We have transitioned away from this class. All new code should use the
    'net' global variable above instead. '''
    def __getattribute__(self, name):
        return getattr(net, name)

    def __setattr__(self, name, value):
        raise RuntimeError('NetworkConstants does not support setting attributes! ({}={})'.format(name,value))
        #setattr(net, name, value)
