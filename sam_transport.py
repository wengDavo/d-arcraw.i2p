"""
I2P SAM v3 transport for D'Arcraw.

Implements the Transport interface against an I2P router's SAM bridge, so every
node is an I2P destination (b32) and all netDb RPC rides inside I2P. STREAM style:
the session control socket stays open, each outbound RPC opens a STREAM CONNECT
socket, and an accept loop handles inbound RPC. Messages are length-prefixed
(4-byte big-endian) because a SAM stream is a raw byte pipe with no boundaries.

This speaks to a live SAM bridge (default 127.0.0.1:7656), so the SAM dialogue
cannot be tested without a running I2P router and must be validated against one.
The framing and b32 helpers are pure and are covered by the package tests.

Persistent identity: SESSION CREATE with DESTINATION=TRANSIENT makes SAM return a
fresh private key in session.private_key. Save it and pass it back as private_key
next start to keep the same b32 across restarts.
"""
import base64
import hashlib
import socket
import struct
import threading

from transport import Transport

SAM_HOST = "127.0.0.1"
SAM_PORT = 7656


class SAMError(Exception):
    pass


def dest_to_b32(dest_b64: str) -> str:
    """I2P destination (I2P-base64) to its .b32.i2p address."""
    std = dest_b64.replace("-", "+").replace("~", "/")
    raw = base64.b64decode(std)
    h = hashlib.sha256(raw).digest()
    return base64.b32encode(h).decode().lower().rstrip("=") + ".b32.i2p"


def _write_framed(sock, data: bytes):
    sock.sendall(struct.pack(">I", len(data)) + data)


def _read_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise SAMError("connection closed")
        buf += chunk
    return buf


def _read_framed(sock) -> bytes:
    (n,) = struct.unpack(">I", _read_exact(sock, 4))
    return _read_exact(sock, n)


def _read_line(sock) -> bytes:
    buf = b""
    while not buf.endswith(b"\n"):
        c = sock.recv(1)
        if not c:
            raise SAMError("connection closed during line read")
        buf += c
    return buf


def _parse_kv(line: bytes, key: bytes):
    for tok in line.split():
        if tok.startswith(key + b"="):
            return tok[len(key) + 1:].decode()
    return None


def _hello(sock):
    sock.sendall(b"HELLO VERSION MIN=3.0 MAX=3.3\n")
    line = _read_line(sock)
    if b"RESULT=OK" not in line:
        raise SAMError("HELLO failed: %r" % line)


class SAMSession:
    def __init__(self, nick, private_key=None, host=SAM_HOST, port=SAM_PORT, sig_type=7):
        self.nick = nick
        self.host = host
        self.port = port
        self._ctrl = socket.create_connection((host, port))
        _hello(self._ctrl)
        dest = private_key or "TRANSIENT"
        self._ctrl.sendall(
            ("SESSION CREATE STYLE=STREAM ID=%s DESTINATION=%s SIGNATURE_TYPE=%d\n"
             % (nick, dest, sig_type)).encode())
        reply = _read_line(self._ctrl)
        if b"RESULT=OK" not in reply:
            raise SAMError("SESSION CREATE failed: %r" % reply)
        self.private_key = _parse_kv(reply, b"DESTINATION") or private_key
        self._b32 = self._lookup_me()

    def _lookup_me(self) -> str:
        s = socket.create_connection((self.host, self.port))
        try:
            _hello(s)
            s.sendall(b"NAMING LOOKUP NAME=ME\n")
            line = _read_line(s)
            dest = _parse_kv(line, b"VALUE")
            if not dest:
                raise SAMError("NAMING LOOKUP ME failed: %r" % line)
            return dest_to_b32(dest)
        finally:
            s.close()

    @property
    def b32(self) -> str:
        return self._b32

    def connect(self, dest_b32: str):
        s = socket.create_connection((self.host, self.port))
        _hello(s)
        s.sendall(("STREAM CONNECT ID=%s DESTINATION=%s SILENT=false\n"
                   % (self.nick, dest_b32)).encode())
        status = _read_line(s)
        if b"RESULT=OK" not in status:
            s.close()
            raise SAMError("STREAM CONNECT failed: %r" % status)
        return s

    def accept(self):
        s = socket.create_connection((self.host, self.port))
        _hello(s)
        s.sendall(("STREAM ACCEPT ID=%s SILENT=false\n" % self.nick).encode())
        status = _read_line(s)
        if b"RESULT=OK" not in status:
            s.close()
            raise SAMError("STREAM ACCEPT failed: %r" % status)
        peer = _read_line(s).strip()     # remote destination on the first line
        return s, peer

    def close(self):
        try:
            self._ctrl.close()
        except Exception:
            pass


class SAMTransport(Transport):
    def __init__(self, nick, private_key=None, host=SAM_HOST, port=SAM_PORT):
        self.session = SAMSession(nick, private_key, host, port)
        self._handler = None
        self._serving = False

    @property
    def address(self) -> str:
        return self.session.b32

    def send(self, dest: str, msg: bytes) -> bytes:
        s = self.session.connect(dest)
        try:
            _write_framed(s, msg)
            return _read_framed(s)
        finally:
            s.close()

    def serve(self, handler) -> None:
        self._handler = handler
        self._serving = True
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def _accept_loop(self):
        while self._serving:
            try:
                s, peer = self.session.accept()
            except Exception:
                continue
            threading.Thread(target=self._handle_conn, args=(s, peer), daemon=True).start()

    def _handle_conn(self, s, peer):
        try:
            req = _read_framed(s)
            resp = self._handler(peer, req)
            _write_framed(s, resp)
        except Exception:
            pass
        finally:
            s.close()

    def stop(self):
        self._serving = False
        self.session.close()
