from enum import IntEnum
from collections.abc import Mapping

import struct
import plistlib

import lief


# https://opensource.apple.com/source/Security/Security-55471/sec/Security/Tool/codesign.c

CSMAGIC_REQUIREMENT = 0xfade0c00
CSMAGIC_REQUIREMENTS = 0xfade0c01
CSMAGIC_CODEDIRECTORY = 0xfade0c02
CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0
CSMAGIC_DETACHED_SIGNATURE = 0xfade0cc1

# https://opensource.apple.com/source/xnu/xnu-2422.1.72/bsd/sys/codesign.h

CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xfade7171

# https://opensource.apple.com/source/Security/Security-57031.30.12/Security/libsecurity_codesigning/lib/CSCommon.h

class CSFlags(IntEnum):
    kSecCodeSignatureHost = 0x0001    # may host guest code
    kSecCodeSignatureAdhoc = 0x0002   # must be used without signer
    kSecCodeSignatureForceHard = 0x0100  # always set HARD mode on launch
    kSecCodeSignatureForceKill = 0x0200  # always set KILL mode on launch
    kSecCodeSignatureForceExpiration = 0x0400  # force certificate expiration checks
    kSecCodeSignatureRestrict = 0x0800  # restrict dyld loading
    kSecCodeSignatureEnforcement = 0x1000  # enforce code signing
    kSecCodeSignatureLibraryValidation = 0x2000  # library validation required


class Flag(object):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        flags = [name for name, flag in CSFlags.__members__.items() if (self.value & flag) == flag]
        return ' | '.join(flags) if len(flags) else 'None'

    def __repr__(self):
        return str(self)

    def __int__(self):
        return self.value

    def __contains__(self, flag):
        return self.value & flag


class Entitlement(Mapping):
    def __init__(self, xml):
        self.xml = xml.decode('utf8')
        try:
            self.storage = plistlib.loads(xml)
        except plistlib.InvalidFileException:
            self.storage = {}
    
    def __str__(self):
        return str(self.storage)

    def __iter__(self):
        return iter(self.storage)

    def __getitem__(self, key):
        return self.storage[key]

    def __len__(self):
        return len(self.storage)

    def dump(self):
        return self.xml

    def as_dict(self):
        return self.storage


class CodeSign(object):
    flags = Flag(0)
    entitlement = Entitlement(b'')


def parse(data):   
    index = 12
    magic, _, count = struct.unpack('>III', data[0:index])
    if magic != CSMAGIC_EMBEDDED_SIGNATURE:
        return None

    result = CodeSign()
    for i in range(count):
        base = index + i * 8
        _, offset = struct.unpack('>2I', data[base:base + 8])
        magic, length = struct.unpack('>2I', data[offset:offset + 8])

        if magic == CSMAGIC_CODEDIRECTORY:
            flag, = struct.unpack('>I', data[offset + 12: offset + 16])
            result.flags = Flag(flag)

        elif magic == CSMAGIC_EMBEDDED_ENTITLEMENTS:
            xml = data[offset + 8:offset + length]
            result.entitlement = Entitlement(xml)

    return result


def parse_file(binary, filename):
    try:
        cs = binary.code_signature
    except lief.not_found:
        return None

    with open(filename, 'rb') as fp:
        fp.seek(cs.data_offset + binary.fat_offset)
        buf = fp.read(cs.data_size)

    return parse(buf)


def main(filename):
    o = lief.parse(filename)
    if not o:
        raise IOError('Invalid macho format')

    result = parse_file(o, filename)
    if not result:
        raise RuntimeError('not signed')

    print('Code signature of %s:' % filename)
    from pprint import pprint
    pprint(result.__dict__)

    # print(list(result.entitlement.keys()))
    # print(hex(int(result.flags)))

if __name__ == '__main__':
    import sys
    path = sys.argv[1] if len(sys.argv) == 2 else '/usr/bin/symbols'

    main(path)
