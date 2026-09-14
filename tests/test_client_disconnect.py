"""Pre-forward cancellation checks using loopback clients and fake detection."""
import errno
import http.client
import json
import select
import socket
import struct
import threading
import unittest
from unittest.mock import Mock

from privacy_gateway.protocol import PrivacyBlocked
from privacy_gateway.server import GatewayServer, GatewayState, Handler


class ClientConnectionCheckTests(unittest.TestCase):
    def test_invalid_socket_blocks_with_a_fixed_diagnostic(self):
        handler = object.__new__(Handler)
        handler.connection = Mock()
        handler.connection.getsockopt.side_effect = OSError(errno.EBADF, "synthetic private detail")
        with self.assertRaises(PrivacyBlocked) as caught:
            handler.check_client_connection()
        self.assertNotIn("synthetic private detail", str(caught.exception))

    def test_unexpected_check_error_is_not_treated_as_a_live_connection(self):
        handler = object.__new__(Handler)
        handler.connection = Mock()
        handler.connection.getsockopt.side_effect = TypeError("synthetic programming error")
        with self.assertRaises(TypeError):
            handler.check_client_connection()


class ClientDisconnectGatewayTests(unittest.TestCase):
    def setUp(self):
        self.scanning = threading.Event()
        self.release = threading.Event()
        self.finished = threading.Event()
        self.connections = []
        self.forwarded = []
        test = self

        class Scanner:
            def scan(self, fragments):
                test.scanning.set()
                if not test.release.wait(3):
                    raise RuntimeError("Synthetic scan gate timed out")
                return []

            def snapshot(self):
                return {"enabled": True}

            def close(self):
                test.release.set()

        class RecordingHandler(Handler):
            def read_json(self):
                payload = super().read_json()
                test.connections.append(self.connection)
                return payload

            def finish(self):
                try:
                    super().finish()
                finally:
                    test.finished.set()

        self.state = GatewayState(provider="codex", mode="auto", semantic_scanner=Scanner())
        def transport(path, body, headers):
            test.forwarded.append((path, body))
            return 200, "application/json", b'{"id":"synthetic","object":"response","status":"completed","output":[]}'
        self.state.transport = transport
        self.server = GatewayServer(self.state)
        self.server.RequestHandlerClass = RecordingHandler
        self.worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.worker.start()
        self.client = socket.create_connection(("127.0.0.1", self.server.server_port), timeout=3)

    def tearDown(self):
        self.release.set()
        self.client.close()
        self.state.close()
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(2)

    def begin_request(self):
        body = json.dumps({"model": "synthetic-model", "input": "Synthetic cancellation probe"}).encode()
        headers = (f"POST /proxy/{self.state.proxy_token}/responses HTTP/1.1\r\n"
                   f"Host: 127.0.0.1:{self.server.server_port}\r\n"
                   "Content-Type: application/json\r\n"
                   "Authorization: Bearer synthetic_auth\r\n"
                   f"Content-Length: {len(body)}\r\n\r\n")
        self.client.sendall(headers.encode() + body)
        self.assertTrue(self.scanning.wait(3))
        self.assertEqual(len(self.connections), 1)

    def wait_for_peer_signal(self):
        # Wait without consuming the pending reset through recv/SO_ERROR.
        readable, _, _ = select.select(self.connections, [], [], 2)
        self.assertEqual(readable, self.connections)

    def test_reset_during_local_scan_never_reaches_the_provider(self):
        self.begin_request()
        self.client.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        self.client.close()
        self.wait_for_peer_signal()
        self.release.set()
        self.assertTrue(self.finished.wait(3))
        self.assertEqual(self.forwarded, [])
        self.assertEqual(self.state.forwarded, 0)
        self.assertEqual(self.state.blocked, 1)
        self.assertIsNone(self.state._credential_fingerprint)

    def test_write_half_close_during_local_scan_still_receives_the_response(self):
        self.begin_request()
        self.client.shutdown(socket.SHUT_WR)
        self.wait_for_peer_signal()
        self.release.set()
        response = http.client.HTTPResponse(self.client)
        response.begin()
        self.assertEqual(response.status, 200)
        self.assertEqual(json.loads(response.read())["status"], "completed")
        response.close()
        self.assertTrue(self.finished.wait(3))
        self.assertEqual(len(self.forwarded), 1)
        self.assertEqual(self.state.forwarded, 1)
        self.assertEqual(self.state.blocked, 0)
