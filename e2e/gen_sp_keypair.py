#!/usr/bin/env python3
"""Generate a self-signed SP keypair for testing signed AuthnRequests (#69).

Writes sp-key.pem and sp-cert.pem into the target directory; register the
certificate in settings.yaml:

    saml:
      want_authn_requests_signed: true
      sp_certificates:
        - /path/to/sp-cert.pem

Usage:
    python e2e/gen_sp_keypair.py [--out DIR] [--cn COMMON_NAME]
"""

import argparse
import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default=".", help="Output directory (default: .)")
    parser.add_argument("--cn", default="test-sp", help="Certificate CN (default: test-sp)")
    args = parser.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, args.cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )

    key_path = out / "sp-key.pem"
    cert_path = out / "sp-cert.pem"
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print(f"Wrote {key_path} and {cert_path} (CN={args.cn})")


if __name__ == "__main__":
    main()
