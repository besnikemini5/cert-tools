"""cert_report.py - report on X.509 certificates in a folder.

Shows subject, issuer, expiry, days left, CA flag and Extended Key Usage
for every certificate, and flags certificates that are expired or expire soon.
"""
import argparse
import csv
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509

CERT_EXTENSIONS = {".crt", ".pem", ".cer"}


def load_cert(path):
    data = path.read_bytes()
    try:
        return x509.load_pem_x509_certificate(data)
    except ValueError:
        return x509.load_der_x509_certificate(data)


def not_after(cert):
    # cryptography 42+ has not_valid_after_utc; older versions only not_valid_after
    if hasattr(cert, "not_valid_after_utc"):
        return cert.not_valid_after_utc
    return cert.not_valid_after.replace(tzinfo=timezone.utc)


def is_ca(cert):
    try:
        return cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        return False


def eku(cert):
    try:
        usages = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        return ", ".join(getattr(u, "_name", None) or u.dotted_string for u in usages)
    except x509.ExtensionNotFound:
        return "-"


def inspect(path, warn_days):
    cert = load_cert(path)
    expires = not_after(cert)
    days_left = (expires - datetime.now(timezone.utc)).days
    if days_left < 0:
        status = "EXPIRED"
    elif days_left <= warn_days:
        status = "EXPIRING"
    else:
        status = "OK"
    return {
        "file": str(path),
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "expires": expires.strftime("%Y-%m-%d"),
        "days_left": days_left,
        "ca": "yes" if is_ca(cert) else "no",
        "eku": eku(cert),
        "status": status,
    }


def main():
    parser = argparse.ArgumentParser(description="Report on X.509 certificates in a folder.")
    parser.add_argument("folder", help="folder to scan (subfolders included)")
    parser.add_argument("--days", type=int, default=30,
                        help="warn when a certificate expires within this many days (default 30)")
    parser.add_argument("--csv", help="also save the report to this CSV file")
    args = parser.parse_args()

    files = sorted(p for p in Path(args.folder).rglob("*") if p.suffix.lower() in CERT_EXTENSIONS)
    if not files:
        print(f"No certificate files found in {args.folder}")
        return 2

    rows = []
    for path in files:
        try:
            rows.append(inspect(path, args.days))
        except ValueError as err:
            print(f"SKIPPED {path}: not a readable certificate ({err})")

    print(f"{'STATUS':<9} {'DAYS':>5}  {'EXPIRES':<10}  {'CA':<3}  {'EKU':<12}  SUBJECT")
    for r in rows:
        print(f"{r['status']:<9} {r['days_left']:>5}  {r['expires']:<10}  {r['ca']:<3}  {r['eku']:<12}  {r['subject']}")

    if args.csv:
        with open(args.csv, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)
        print(f"\nSaved report to {args.csv}")

    problems = [r for r in rows if r["status"] != "OK"]
    print(f"\n{len(rows)} certificates checked, {len(problems)} expired or expiring within {args.days} days")
    # Non-zero exit code lets other scripts or schedulers react to problems
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())