"""Explicitly enabled, certificate-pinned TLS transport for ICMP-only probe exports.

No LAN discovery, inbound listener on startup, automatic firewall changes or
secret persistence. Peer IP, fingerprint and bearer key are entered explicitly.
Authenticated source means access to a paired session, NOT validated ICMP truth.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
from pathlib import Path
import queue
import secrets
import ssl
import tempfile
import threading
from typing import Callable

from . import distributed_probes as probes

PORT_MIN, PORT_MAX = 1024, 65535
MAX_POST_BYTES = probes.MAX_BYTES
SESSION_AGE_SECONDS = 180


def allowed_ip(value: str) -> str:
    """Only an explicit IPv4 LAN or loopback address; never public/wildcard bind."""
    if type(value) is not str:
        raise ValueError('Нужен явный локальный IPv4')
    ip = ipaddress.IPv4Address(value)
    private = any(ip in net for net in (ipaddress.IPv4Network('10.0.0.0/8'),
                  ipaddress.IPv4Network('172.16.0.0/12'),
                  ipaddress.IPv4Network('192.168.0.0/16'),
                  ipaddress.IPv4Network('127.0.0.0/8')))
    if not private:
        raise ValueError('Разрешены только локальные адреса RFC1918 или loopback')
    return str(ip)


def allowed_port(value) -> int:
    if type(value) is not int or not PORT_MIN <= value <= PORT_MAX:
        raise ValueError('Порт должен быть от 1024 до 65535')
    return value


def validate_fingerprint(fingerprint: str) -> str:
    if type(fingerprint) is not str:
        raise ValueError('Отпечаток SHA-256 должен быть строкой')
    value = fingerprint.replace(':', '').lower().strip()
    if len(value) != 64 or any(x not in '0123456789abcdef' for x in value):
        raise ValueError('Нужен полный SHA-256 сертификата (64 hex символа)')
    return value


def validate_token(token: str) -> str:
    if type(token) is not str or len(token) != 64 or any(x not in '0123456789abcdef' for x in token):
        raise ValueError('Нужен 64-символьный код доступа')
    return token


def _tls_credentials(directory: Path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    now = datetime.now(timezone.utc)
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'BLOODSKY NET local peer')]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'BLOODSKY NET local peer')]))
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(hours=24))
            .add_extension(x509.BasicConstraints(ca=False,path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    private_path = directory / 'peer-key.pem'
    cert_path = directory / 'peer-cert.pem'
    private_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    fingerprint = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    return str(cert_path), str(private_path), fingerprint


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 8


class PeerReceiver:
    """Start only after a user confirms the bind address; call stop on app close."""
    def __init__(self, host: str = '127.0.0.1', port: int = 18443):
        self.host = allowed_ip(host)
        self.port = allowed_port(port)
        self.token = secrets.token_hex(32)
        self.fingerprint = ''
        self.incoming: queue.Queue[probes.ProbeSnapshot] = queue.Queue(maxsize=64)
        self._tmp = None
        self._httpd = None
        self._thread = None
        self._ids = set()
        self._ids_lock = threading.Lock()

    def start(self):
        if self._httpd is not None:
            raise RuntimeError('Приём уже включён')
        tmp = tempfile.TemporaryDirectory(prefix='bloodsky-probe-tls-')
        server = None
        try:
            cert, key, fingerprint = _tls_credentials(Path(tmp.name))
            owner = self

            class Handler(BaseHTTPRequestHandler):
                def log_message(self, *_args):
                    pass  # Never log pairing token, body or peer data.

                def do_POST(self):
                    if self.path != '/probe':
                        self.send_error(404); return
                    if not hmac.compare_digest(self.headers.get('Authorization', ''), 'Bearer '+owner.token):
                        self.send_error(401); return
                    try:
                        size = int(self.headers.get('Content-Length', '-1'))
                        if not 0 < size <= MAX_POST_BYTES:
                            self.send_error(413); return
                        raw = self.rfile.read(size)
                        snapshot = probes.decode(raw)
                        delta = (datetime.now(timezone.utc)-snapshot.created_at).total_seconds()
                        if not -5 <= delta <= SESSION_AGE_SECONDS:
                            self.send_error(422); return
                        with owner._ids_lock:
                            if snapshot.ident in owner._ids:
                                self.send_error(409); return
                            if owner.incoming.full():
                                self.send_error(503); return
                            owner._ids.add(snapshot.ident)
                            if len(owner._ids) > 512:
                                owner._ids.clear()
                                owner._ids.add(snapshot.ident)
                            owner.incoming.put_nowait(snapshot)
                        self.send_response(202)
                        self.send_header('Content-Length', '0')
                        self.end_headers()
                    except (ValueError, TypeError, UnicodeError):
                        self.send_error(400)

                def do_GET(self):
                    self.send_error(405)

            server = _Server((self.host, self.port), Handler)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(cert, key)
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, name='BloodskyProbeTLS',daemon=True)
            thread.start()
            self._httpd, self._thread, self._tmp = server,thread,tmp
            self.fingerprint = fingerprint
            self.port = server.server_address[1]
        except Exception:
            if server: server.server_close()
            tmp.cleanup()
            raise
        return self

    def stop(self):
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._thread.join(timeout=3)
            self._httpd = None
            self._thread = None
        if self._tmp is not None:
            self._tmp.cleanup()
            self._tmp = None
        self.token = ''


def send_snapshot(host: str, port: int, fingerprint: str, token: str,
                  snapshot: probes.ProbeSnapshot, timeout: float = 5.0) -> None:
    """Verify peer cert *before* writing either the key or the ICMP payload."""
    host = allowed_ip(host)
    port = allowed_port(port)
    digest = validate_fingerprint(fingerprint)
    token = validate_token(token)
    payload = probes.encode(snapshot)
    if not -5 <= (datetime.now(timezone.utc)-snapshot.created_at).total_seconds() <= SESSION_AGE_SECONDS:
        raise ValueError('Нужны свежие измерения, выполните мониторинг заново')
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # The exact SHA-256 leaf pin is checked below.
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    conn = http.client.HTTPSConnection(host,port,timeout=timeout,context=ctx)
    try:
        conn.connect()
        der = conn.sock.getpeercert(binary_form=True)
        if not der or not hmac.compare_digest(hashlib.sha256(der).hexdigest(), digest):
            raise ssl.SSLError('Отпечаток сертификата не совпадает; данные не отправлены')
        conn.request('POST','/probe',body=payload,headers={'Authorization':'Bearer '+token,
                     'Content-Type':'application/json','Content-Length':str(len(payload))})
        response=conn.getresponse()
        response.read(1024)
        if response.status != 202:
            raise ValueError('Получатель отклонил пакет (HTTP '+str(response.status)+')')
    finally:
        conn.close()
