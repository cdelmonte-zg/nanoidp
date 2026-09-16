"""An HTTPS origin for the metadata-document tests (#196, PR B).

A private CA and a certificate for a name that does not exist in DNS, so the
fetcher has to be told the address while proving the name: the whole point
of the pinned connection is that those are two different things.

Kept out of the test module so it reads as what it is, a harness, and so a
later e2e suite can use the same one.
"""

import datetime
import http.server
import json
import ssl
import threading
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

HOSTNAME = "client.example"
DOCUMENT_PATH = "/metadata.json"


def _key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def issue_certificates(directory: Path, hostname: str = HOSTNAME) -> Tuple[Path, Path]:
    """A CA and a server certificate for ``hostname``. Returns both paths."""
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = _key()
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "nanoidp test CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    server_key = _key()
    server = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    ca_path = directory / "ca.pem"
    server_path = directory / "server.pem"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    server_path.write_bytes(
        server.public_bytes(serialization.Encoding.PEM)
        + server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return ca_path, server_path


def metadata_document(client_id: str, **overrides: Any) -> Dict[str, Any]:
    document: Dict[str, Any] = {
        "client_id": client_id,
        "redirect_uris": ["http://localhost:3000/callback"],
        "token_endpoint_auth_method": "none",
    }
    document.update(overrides)
    return document


class Origin:
    """The server the document is fetched from, and what it answers.

    Every attribute is something a test wants to vary: the status, the
    content type, the body, how slowly it arrives, whether it redirects.
    """

    def __init__(self, server_pem: Path) -> None:
        self.status = 200
        self.content_type = "application/json"
        self.body: bytes = b""
        self.cache_control: Optional[str] = None
        self.location: Optional[str] = None
        self.chunk_delay = 0.0
        self.chunk_size = 0
        self.requests: list = []
        self._server_pem = server_pem
        self._httpd: Optional[http.server.HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def serve_document(self, document: Dict[str, Any]) -> None:
        self.body = json.dumps(document).encode()

    @property
    def port(self) -> int:
        assert self._httpd is not None
        return self._httpd.server_address[1]

    def __enter__(self) -> "Origin":
        origin = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self) -> None:  # noqa: N802 - the stdlib's name
                origin.requests.append((self.path, dict(self.headers)))
                if origin.location is not None:
                    self.send_response(origin.status)
                    self.send_header("Location", origin.location)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                self.send_response(origin.status)
                if origin.content_type:
                    self.send_header("Content-Type", origin.content_type)
                if origin.cache_control:
                    self.send_header("Cache-Control", origin.cache_control)
                if origin.chunk_size:
                    # No Content-Length: a limit that trusted one would not
                    # be a limit.
                    self.send_header("Transfer-Encoding", "chunked")
                    self.end_headers()
                    self._drip()
                    return
                self.send_header("Content-Length", str(len(origin.body)))
                self.end_headers()
                self.wfile.write(origin.body)

            def _drip(self) -> None:
                import time as _time

                for start in range(0, len(origin.body), origin.chunk_size):
                    piece = origin.body[start : start + origin.chunk_size]
                    try:
                        self.wfile.write(
                            hex(len(piece))[2:].encode() + b"\r\n" + piece + b"\r\n"
                        )
                        self.wfile.flush()
                    except OSError:
                        return
                    if origin.chunk_delay:
                        _time.sleep(origin.chunk_delay)
                try:
                    self.wfile.write(b"0\r\n\r\n")
                except OSError:
                    return

            def log_message(self, *args: Any) -> None:
                return

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self._server_pem)
        self._httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._httpd.socket = context.wrap_socket(self._httpd.socket, server_side=True)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc_info: Any) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
