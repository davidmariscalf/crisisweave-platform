from __future__ import annotations

import threading
from http.server import ThreadingHTTPServer


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """Threading HTTP server with a hard concurrency ceiling and socket timeout.

    The standard ThreadingHTTPServer creates one thread per accepted connection.
    On a small VM, a burst of slow clients can otherwise consume unbounded memory.
    """

    daemon_threads = True
    block_on_close = False
    allow_reuse_address = True
    request_queue_size = 128

    def __init__(self, server_address, handler_cls, *, max_workers=64, socket_timeout=10.0):
        self.max_workers = max(1, int(max_workers))
        self.socket_timeout = max(1.0, float(socket_timeout))
        self._worker_slots = threading.BoundedSemaphore(self.max_workers)
        super().__init__(server_address, handler_cls)

    def get_request(self):
        request, client_address = super().get_request()
        request.settimeout(self.socket_timeout)
        return request, client_address

    def process_request(self, request, client_address):
        if not self._worker_slots.acquire(blocking=False):
            try:
                request.sendall(
                    b"HTTP/1.1 503 Service Unavailable\r\n"
                    b"Connection: close\r\n"
                    b"Cache-Control: no-store\r\n"
                    b"Content-Length: 0\r\n\r\n"
                )
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._worker_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._worker_slots.release()
