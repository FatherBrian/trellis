"""A TCP relay the demo and tests put between Trellis and Postgres, to cut it on cue.

From Trellis's side, cutting the relay is Postgres going away: open connections drop and
new ones are refused. ``resume()`` brings it back.
"""

from __future__ import annotations

import contextlib
import socket
import threading


class Relay:
    def __init__(self, target_host: str, target_port: int) -> None:
        self.target = (target_host, target_port)
        self._listener: socket.socket | None = None
        self._conns: list[socket.socket] = []
        self._lock = threading.Lock()
        self.port = 0
        self.resume()

    def resume(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", self.port))
        listener.listen(16)
        self.port = listener.getsockname()[1]
        self._listener = listener
        threading.Thread(target=self._accept, args=(listener,), daemon=True).start()

    def _accept(self, listener: socket.socket) -> None:
        while True:
            try:
                client, _ = listener.accept()
            except OSError:
                return
            try:
                upstream = socket.create_connection(self.target, timeout=5)
            except OSError:
                client.close()
                continue
            upstream.settimeout(None)
            with self._lock:
                self._conns += [client, upstream]
            for a, b in ((client, upstream), (upstream, client)):
                threading.Thread(target=self._pipe, args=(a, b), daemon=True).start()

    @staticmethod
    def _pipe(src: socket.socket, dst: socket.socket) -> None:
        try:
            while data := src.recv(65536):
                dst.sendall(data)
        except OSError:
            pass
        finally:
            for s in (src, dst):
                with contextlib.suppress(OSError):
                    s.shutdown(socket.SHUT_RDWR)

    def cut(self) -> None:
        """Drop every open connection and refuse new ones."""
        if self._listener is not None:
            # shutdown() wakes the thread blocked in accept(); close() alone wouldn't, and
            # the socket would keep listening.
            with contextlib.suppress(OSError):
                self._listener.shutdown(socket.SHUT_RDWR)
            self._listener.close()
            self._listener = None
        with self._lock:
            conns, self._conns = self._conns, []
        for s in conns:
            with contextlib.suppress(OSError):
                s.shutdown(socket.SHUT_RDWR)
            s.close()

    def close(self) -> None:
        self.cut()


def relayed(url: str) -> tuple[Relay, str]:
    """A relay in front of a postgresql:// URL, and the URL that goes through it."""
    scheme, rest = url.split("://", 1)
    creds, _, hostpart = rest.rpartition("@")
    hostport, _, db = hostpart.partition("/")
    host, _, port = hostport.partition(":")
    relay = Relay(host or "127.0.0.1", int(port or 5432))
    auth = f"{creds}@" if creds else ""
    return relay, f"{scheme}://{auth}127.0.0.1:{relay.port}/{db}"
