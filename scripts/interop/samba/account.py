#!/usr/bin/python3
"""Account changes of the Samba AD DC interop fixture (lane 1E).

Runs inside the fixture container against the local sam.ldb with the system
session. Passwords are read from the environment variable named on the command
line (loaded from the run's tmpfs secrets), never from argv, and never printed.

    account.py create NAME PASSWORD_VARIABLE [ATTRIBUTE=VALUE...]
    account.py password NAME PASSWORD_VARIABLE
    account.py uac NAME FLAG...            (FLAG: DONT_REQUIRE_PREAUTH)
    account.py enctypes NAME VALUE         (msDS-SupportedEncryptionTypes)
"""

import os
import sys

import ldb
from samba.auth import system_session
from samba.param import LoadParm
from samba.samdb import SamDB

UAC_FLAGS = {"DONT_REQUIRE_PREAUTH": 0x00400000}


def open_samdb() -> SamDB:
    lp = LoadParm()
    lp.load_default()
    return SamDB(url=lp.samdb_url(), session_info=system_session(), lp=lp)


def account_filter(name: str) -> str:
    return "(sAMAccountName=%s)" % ldb.binary_encode(name)


def account_dn(samdb: SamDB, name: str) -> ldb.Dn:
    found = samdb.search(
        base=samdb.domain_dn(),
        scope=ldb.SCOPE_SUBTREE,
        expression=account_filter(name),
        attrs=[],
    )
    if len(found) != 1:
        raise SystemExit("account %s: %d matches" % (name, len(found)))
    return found[0].dn


def replace(samdb: SamDB, name: str, attribute: str, value: str) -> None:
    message = ldb.Message(account_dn(samdb, name))
    message[attribute] = ldb.MessageElement(value, ldb.FLAG_MOD_REPLACE, attribute)
    samdb.modify(message)


def main(argv: list[str]) -> None:
    if len(argv) < 3:
        raise SystemExit(__doc__)
    action, name = argv[1], argv[2]
    samdb = open_samdb()
    if action == "create":
        samdb.newuser(name, os.environ[argv[3]], useusernameascn=True)
        for assignment in argv[4:]:
            attribute, _, value = assignment.partition("=")
            replace(samdb, name, attribute, value)
    elif action == "password":
        samdb.setpassword(
            account_filter(name),
            os.environ[argv[3]],
            force_change_at_next_login=False,
            username=name,
        )
    elif action == "uac":
        for flag in argv[3:]:
            samdb.toggle_userAccountFlags(
                account_filter(name), UAC_FLAGS[flag], flag, on=True, strict=True
            )
    elif action == "enctypes":
        replace(samdb, name, "msDS-SupportedEncryptionTypes", str(int(argv[3], 0)))
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main(sys.argv)
