import argparse
import getpass
import sys

from .admin_recovery import AdminRecoveryError, reset_admin_password
from .database import SessionLocal


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(description="LayerScope server-local administrative recovery")
    actions = command.add_subparsers(dest="action", required=True)
    reset = actions.add_parser("reset-admin-password", help="Reset an active administrator after MFA verification")
    reset.add_argument("--username", help="Administrator username; optional when exactly one active admin exists")
    return command


def run(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if not sys.stdin.isatty():
        print("Recovery requires an interactive terminal; do not pipe passwords or codes.", file=sys.stderr)
        return 2
    if args.action != "reset-admin-password":
        return 2
    password = getpass.getpass("New password: ")
    confirmation = getpass.getpass("Confirm new password: ")
    if password != confirmation:
        print("The passwords do not match.", file=sys.stderr)
        return 2
    code = getpass.getpass("Current 6-digit authenticator or unused recovery code: ")
    try:
        with SessionLocal() as db:
            result = reset_admin_password(db, args.username, password, code)
    except AdminRecoveryError as exc:
        print(f"Password reset failed: {exc}", file=sys.stderr)
        return 1
    except Exception:
        print("Password reset failed because the local authentication store is unavailable.", file=sys.stderr)
        return 1
    print(f"Password reset completed for {result['username']}. All existing sessions were revoked.")
    if result["recovery_code_used"]:
        print("The supplied recovery code was consumed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
