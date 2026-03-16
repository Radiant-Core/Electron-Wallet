#-----------------------------------------------------------------------------
#  Copyright (C) 2019 Alberto Sottile
#
#  Distributed under the terms of the 3-clause BSD License.
#-----------------------------------------------------------------------------

import ctypes
import ctypes.util

appkit = ctypes.cdll.LoadLibrary(ctypes.util.find_library('AppKit'))
objc = ctypes.cdll.LoadLibrary(ctypes.util.find_library('objc'))

void_p = ctypes.c_void_p
char_p = ctypes.c_char_p

objc.objc_getClass.restype = void_p
objc.objc_getClass.argtypes = [char_p]
objc.sel_registerName.restype = void_p
objc.sel_registerName.argtypes = [char_p]
objc.objc_msgSend.restype = void_p


def _utf8(s):
    if not isinstance(s, bytes):
        s = s.encode('utf8')
    return s


def _msg(receiver, selector, *args):
    argtypes = [void_p, void_p]
    call_args = [receiver, selector]
    for arg in args:
        if isinstance(arg, bytes):
            argtypes.append(char_p)
            call_args.append(arg)
        elif isinstance(arg, int):
            argtypes.append(void_p)
            call_args.append(void_p(arg))
        else:
            argtypes.append(void_p)
            call_args.append(arg)
    fn = ctypes.CFUNCTYPE(void_p, *argtypes)(('objc_msgSend', objc))
    return fn(*call_args)


def n(name):
    return objc.sel_registerName(_utf8(name))


def C(classname):
    return objc.objc_getClass(_utf8(classname))


def theme():
    NSAutoreleasePool = C('NSAutoreleasePool')
    pool = _msg(NSAutoreleasePool, n('alloc'))
    pool = _msg(pool, n('init'))

    NSUserDefaults = C('NSUserDefaults')
    stdUserDef = _msg(NSUserDefaults, n('standardUserDefaults'))

    NSString = C('NSString')

    key = _msg(NSString, n('stringWithUTF8String:'), _utf8('AppleInterfaceStyle'))
    appearanceNS = _msg(stdUserDef, n('stringForKey:'), key)
    appearanceC = _msg(appearanceNS, n('UTF8String')) if appearanceNS else None

    if appearanceC is not None:
        out = ctypes.string_at(appearanceC)
    else:
        out = None

    _msg(pool, n('release'))

    if out is not None:
        return out.decode('utf-8')
    else:
        return 'Light'


def isDark():
    return theme() == 'Dark'


def isLight():
    return theme() == 'Light'
