"""Интеграционные проверки локального экземпляра oproxy."""
import contextlib
from concurrent.futures import ThreadPoolExecutor
import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
HELLO = bytes.fromhex("53f5c61a7b")
END = bytes.fromhex("6653b2a6")
PING = bytes.fromhex("214754b3")
CHECKS = Path(__file__).with_name("ПроверкиТестовогоПрокси.os")


def request(alias="test", method="DevDepot_changeVersion", data=b""):
    xml = ('<?xml version="1.0" encoding="UTF-8"?>'
           '<crs:call xmlns:crs="http://v8.1c.ru/8.2/crs" alias="%s" name="%s" version="8.3.22.2143">'
           '<crs:auth user="Tester"/><crs:comment>частями</crs:comment><crs:data>' % (alias, method))
    body = b"\xef\xbb\xbf" + xml.encode() + data + b"</crs:data></crs:call>"
    return b"POST  HTTP/1.1\r\nContent-Length: %d\r\nContent-Type: application/xml\r\n\r\n" % len(body) + body + END


def response(body=b"OK"):
    return b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body + END


def receive(sock, expected):
    result = bytearray()
    while len(result) < len(expected):
        part = sock.recv(min(65536, len(expected) - len(result)))
        if not part:
            raise AssertionError("EOF at %d of %d bytes" % (len(result), len(expected)))
        result.extend(part)
    if result != expected:
        raise AssertionError("payload changed (%d bytes)" % len(result))


def eof(sock):
    try:
        if sock.recv(1) != b"":
            raise AssertionError("unexpected data before EOF")
    except ConnectionResetError:
        pass


def abort(sock):
    linger = struct.pack("HH" if os.name == "nt" else "ii", 1, 0)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)
    sock.close()


def split_send(sock, data, cuts):
    start = 0
    for end in sorted(set(cuts)):
        sock.sendall(data[start:end])
        time.sleep(0.012)
        start = end
    sock.sendall(data[start:])


class Proxy:
    def __init__(self, *, writable_temp=True, env=None):
        self.resources = contextlib.ExitStack()
        self.writable_temp = writable_temp
        self.env = env or {}

    def __enter__(self):
        try:
            self.start()
        except BaseException:
            self.resources.close()
            raise
        return self

    def __exit__(self, *exc):
        self.resources.close()

    def start(self):
        temp = Path(self.resources.enter_context(tempfile.TemporaryDirectory()))
        hook = temp / "checks.os"
        hook.write_bytes(CHECKS.read_bytes())
        # A regular file cannot host any temporary files, even ones removed before the test ends.
        process_temp = str(temp if self.writable_temp else hook)
        self.log = temp / "proxy.log"
        output = self.resources.enter_context(self.log.open("wb"))
        self.storage = self.resources.enter_context(socket.socket())
        self.storage.bind(("127.0.0.1", 0))
        self.storage.listen()
        self.storage.settimeout(5)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            self.port = reservation.getsockname()[1]
        self.process = subprocess.Popen(
            ["oscript", "-encoding=utf-8", str(ROOT / "src" / "main.os"), "start",
             "--proxy-port", str(self.port), "--storage-server", "127.0.0.1",
             "--storage-port", str(self.storage.getsockname()[1]), "--check-file", str(hook)],
            stdout=output, stderr=subprocess.STDOUT, cwd=ROOT,
            env=dict(os.environ, TMP=process_temp, TEMP=process_temp, TMPDIR=process_temp, **self.env),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        self.resources.callback(self.stop)
        deadline = time.monotonic() + 15
        while "Прокси-сервер запущен" not in self.logs():
            if self.process.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError(self.logs())
            time.sleep(0.04)

    def stop(self):
        if self.process.poll() is None:
            self.process.terminate()
        self.process.wait(timeout=5)

    def logs(self):
        return self.log.read_text(encoding="utf-8-sig", errors="replace")

    def client(self):
        sock = socket.create_connection(("127.0.0.1", self.port), 5)
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            receive(sock, HELLO)
        except BaseException:
            sock.close()
            raise
        return sock

    def peer(self, greeting=HELLO):
        sock, _ = self.storage.accept()
        sock.settimeout(5)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.sendall(greeting)
        return sock

    def exchange(self, alias="test"):
        packet = request(alias)
        with self.client() as client:
            client.sendall(packet)
            with self.peer() as peer:
                receive(peer, packet)
                peer.sendall(response())
                receive(client, response())
                client.close()
                eof(peer)

    def assert_no_storage_connection(self, wait=0.3):
        self.storage.settimeout(wait)
        try:
            sock, _ = self.storage.accept()
        except socket.timeout:
            return
        finally:
            self.storage.settimeout(5)
        sock.close()
        raise AssertionError("unexpected storage connection")

    def interrupt_large_request(self, *, reset=False):
        packet = request("tap", "DevDepot_commitObjects", b"A" * (2 * 1024 * 1024))
        with self.client() as client:
            client.sendall(memoryview(packet)[:-128])
            if reset:
                abort(client)
            else:
                # FIN follows the entire incomplete body in TCP byte order.
                client.shutdown(socket.SHUT_WR)
                eof(client)
        # A checked request is sent to the storage only once it is complete and checked.
        self.assert_no_storage_connection(0.05)


class Connections(unittest.TestCase):
    def test_fragmented_and_pipelined(self):
        first = request("tap", "DevDepot_commitObjects")
        next_request = request("next")
        binary_reply = response(b"binary" + END + PING + b"\x00" * 16384)
        with Proxy() as proxy, proxy.client() as client:
            split_send(client, first[:-2], (1, 3, 15, first.index(b"<?xml") + 2,
                                           first.index(b"commitObjects") + 3, first.index("частями".encode()) + 1))
            client.sendall(first[-2:] + PING + next_request)
            with proxy.peer(HELLO[:2]) as peer:
                time.sleep(0.025)
                peer.sendall(HELLO[2:])
                receive(peer, first)
                split_send(peer, binary_reply, (3, 19, len(binary_reply) - 1))
                receive(client, binary_reply)
                receive(peer, PING + next_request)
                peer.sendall(response())
                receive(client, response())
                client.close()
                eof(peer)
            log = proxy.logs().splitlines()
            self.assertEqual(log.count("PRE частями"), 1)
            self.assertEqual(log.count("POST частями"), 1)

    def test_denial_and_retry(self):
        denied = request("deny", data=b"B" * (2 * 1024 * 1024))
        header_end = denied.index(b"\r\n\r\n") + 4
        allowed = request("allowed")
        with Proxy(writable_temp=False) as proxy, proxy.client() as client:
            split_send(client, PING + denied[:header_end], (2, 6, 45))
            with proxy.peer() as peer:
                receive(peer, PING)
                client.sendall(memoryview(denied)[header_end:])
                reply = bytearray()
                while not reply.endswith(END):
                    part = client.recv(4096)
                    self.assertTrue(part)
                    reply.extend(part)
                self.assertIn(b"call_exception", reply)
                client.sendall(allowed)
                receive(peer, allowed)
                peer.sendall(response())
                receive(client, response())

    def test_large_checked_body_in_memory(self):
        # Above the 50 MiB threshold at which some OneScript 1.9 binary APIs use the disk.
        packet = request("tap", "DevDepot_commitObjects", b"A" * (52 * 1024 * 1024))
        for writable_temp in (True, False):
            with self.subTest(writable_temp=writable_temp), Proxy(writable_temp=writable_temp) as proxy:
                with proxy.client() as client:
                    client.settimeout(30)
                    initial_files = set(proxy.log.parent.iterdir())
                    client.sendall(memoryview(packet)[:-128])
                    self.assertEqual(set(proxy.log.parent.iterdir()), initial_files)
                    client.sendall(packet[-128:])
                    with proxy.peer() as peer:
                        peer.settimeout(30)
                        receive(peer, packet)
                        peer.sendall(response())
                        receive(client, response())
                        client.close()
                        eof(peer)
                self.assertEqual(proxy.logs().splitlines().count("POST частями"), 1)

    def test_interrupted_large_request(self):
        with Proxy(writable_temp=False) as proxy:
            proxy.interrupt_large_request()
            proxy.interrupt_large_request(reset=True)
            self.assertNotIn("POST частями", proxy.logs())
            proxy.exchange()

    def test_unchecked_xml_streams_before_end(self):
        packet = request("read", "DevDepot_getObjects", b"C" * 8192)
        prefix = 4096
        with Proxy(writable_temp=False) as proxy, proxy.client() as client:
            client.sendall(packet[:prefix])
            with proxy.peer() as peer:
                receive(peer, packet[:prefix])
                client.sendall(packet[prefix:])
                receive(peer, packet[prefix:])
                peer.sendall(response())
                receive(client, response())

    def test_recording_with_trailing_pings(self):
        recording = (ROOT / "tests" / "ДвоичныеДанныеЗапросаКонфигуратораНаПомещениеДанныхВХранилище.dat").read_bytes()
        end = recording.index(END) + len(END)
        with Proxy() as proxy, proxy.client() as client:
            split_send(client, recording, (2, 31, recording.index(b"<?xml") + 2, end - 2))
            with proxy.peer() as peer:
                receive(peer, recording[:end])
                peer.sendall(response())
                receive(client, response())
                receive(peer, recording[end:])

    def test_binary_passthrough(self):
        body = b"\x00" * 8192 + END + b"inside" + PING + b"tail"
        header = b"POST  HTTP/1.1\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\n\r\n" % len(body)
        raw = b"raw" + END + b"inside" + END
        with Proxy() as proxy, proxy.client() as client:
            client.sendall(header + body[:200])
            with proxy.peer() as peer:
                # Opaque uploads must already be flowing before their end marker arrives.
                receive(peer, header + body[:200])
                split_send(client, body[200:] + END, (len(body) - 198,))
                receive(peer, body[200:] + END)
                peer.sendall(raw)
                receive(client, raw)
                client.sendall(request())
                receive(peer, request())
                peer.sendall(response())
                receive(client, response())

    def test_broken_connections(self):
        packet = request("tap", "DevDepot_commitObjects")
        with Proxy() as proxy:
            with proxy.client() as client:
                client.sendall(packet[:-4])
            proxy.assert_no_storage_connection()
            with proxy.client() as client:
                client.sendall(packet)
                with proxy.peer() as peer:
                    receive(peer, packet)
                    prefix = response(b"test")[:-6]
                    peer.sendall(prefix)
                    peer.close()
                    receive(client, prefix)
                    eof(client)
            with proxy.client() as client:
                client.sendall(packet)
                with proxy.peer() as peer:
                    receive(peer, packet)
                    abort(client)
                    peer.settimeout(38)
                    eof(peer)
            self.assertNotIn("POST частями", proxy.logs())
            proxy.exchange()

    def test_worker_limit_queues_and_reuses_connections(self):
        for limit in (2, 6):
            with self.subTest(limit=limit), Proxy(env={"oproxy_workers": str(limit)}) as proxy:
                with contextlib.ExitStack() as clients:
                    occupied = [clients.enter_context(proxy.client()) for _ in range(limit)]
                    with socket.create_connection(("127.0.0.1", proxy.port), 5) as queued:
                        queued.settimeout(0.75)
                        with self.assertRaises(socket.timeout):
                            queued.recv(1)
                        occupied[0].close()
                        queued.settimeout(5)
                        receive(queued, HELLO)
                        packet = request("snapshot")
                        queued.sendall(packet)
                        with proxy.peer() as storage:
                            receive(storage, packet)
                            storage.sendall(response())
                            receive(queued, response())
                        self.assertIn(f"SNAP {limit} 0 0", proxy.logs().splitlines())
                proxy.exchange()

    def test_one_slow_connection_does_not_block_others(self):
        packet = request()
        with Proxy() as proxy, proxy.client() as slow:
            slow.sendall(packet)
            with proxy.peer() as peer:
                receive(peer, packet)
                proxy.exchange()
                time.sleep(1.6)
                peer.sendall(response())
                receive(slow, response())
                slow.close()
                eof(peer)

    def test_checked_request_connects_after_body(self):
        packet = request("tap", "DevDepot_commitObjects", b"D" * 65536)
        with Proxy() as proxy, proxy.client() as client:
            client.sendall(packet[:-128])
            # While the body arrives and is checked, the storage leg is not needed yet.
            proxy.assert_no_storage_connection(0.5)
            client.sendall(packet[-128:])
            with proxy.peer() as peer:
                receive(peer, packet)
                peer.sendall(response())
                receive(client, response())

    def test_idle_storage_connection_is_replaced(self):
        packet = request()
        with Proxy(env={"oproxy_storage_idle": "1"}) as proxy, proxy.client() as client:
            client.sendall(packet)
            with proxy.peer() as first:
                receive(first, packet)
                first.sendall(response())
                receive(client, response())
                # The proxy does not trust a leg that has been idle too long.
                eof(first)
            client.sendall(packet)
            with proxy.peer() as second:
                receive(second, packet)
                second.sendall(response())
                receive(client, response())
            self.assertNotIn("прерван", proxy.logs())

    def test_slow_download_survives_storage_close(self):
        # The storage may close its leg as soon as it has handed over a long reply,
        # while the proxy is still pushing the tail into a slow client.
        packet = request()
        reply = response(bytes(range(256)) * 1024)
        with Proxy() as proxy, socket.socket() as client:
            client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
            client.connect(("127.0.0.1", proxy.port))
            client.settimeout(5)
            receive(client, HELLO)
            client.sendall(packet)
            peer = proxy.peer()
            receive(peer, packet)

            def send_and_close():
                with peer:
                    peer.settimeout(60)
                    peer.sendall(reply)

            sender = threading.Thread(target=send_and_close)
            sender.start()
            received = bytearray()
            while len(received) < len(reply):
                part = client.recv(2048)
                self.assertTrue(part, "EOF at %d of %d bytes" % (len(received), len(reply)))
                received.extend(part)
                time.sleep(0.05)
            sender.join()
            self.assertEqual(bytes(received), reply)
            # The client leg is still usable, the next request goes over a new storage leg.
            client.sendall(packet)
            with proxy.peer() as second:
                receive(second, packet)
                second.sendall(response())
                receive(client, response())
            self.assertNotIn("прерван", proxy.logs())

    def test_storage_idle_disconnect_reconnects(self):
        packet = request()
        with Proxy() as proxy, proxy.client() as client:
            # Before the watchdog notices the closed storage leg, and after it has released it.
            for pause in (0.3, 2.5):
                client.sendall(packet)
                with proxy.peer() as peer:
                    receive(peer, packet)
                    peer.sendall(response())
                    receive(client, response())
                time.sleep(pause)
            client.sendall(packet)
            with proxy.peer() as peer:
                receive(peer, packet)
                peer.sendall(response())
                receive(client, response())
            closes = [line for line in proxy.logs().splitlines() if "закрыло соединение после" in line]
            self.assertEqual(len(closes), 2)
            for line in closes:
                self.assertRegex(line, r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3} ИНФОРМАЦИЯ - Хранилище ")

    def test_idle_client_receives_probe(self):
        packet = request()
        with Proxy(env={"oproxy_client_probe": "1"}) as proxy, proxy.client() as client:
            client.sendall(packet)
            with proxy.peer() as peer:
                receive(peer, packet)
                peer.sendall(response())
                receive(client, response())
                time.sleep(2.6)
                client.settimeout(0.5)
                probes = bytearray()
                with contextlib.suppress(socket.timeout):
                    while part := client.recv(4096):
                        probes.extend(part)
                self.assertGreaterEqual(len(probes) // len(PING), 1)
                self.assertEqual(bytes(probes), PING * (len(probes) // len(PING)))
                # A probe may still precede the reply, as storage pings do.
                client.settimeout(5)
                client.sendall(packet)
                receive(peer, packet)
                peer.sendall(response())
                reply = bytearray()
                while not reply.endswith(response()):
                    part = client.recv(4096)
                    self.assertTrue(part)
                    reply.extend(part)
                pings = reply[:-len(response())]
                self.assertEqual(bytes(pings), PING * (len(pings) // len(PING)))

    def test_storage_recovers_after_connection_refused(self):
        with Proxy() as proxy:
            address = proxy.storage.getsockname()
            proxy.storage.close()
            with proxy.client() as client:
                client.sendall(request())
                eof(client)
            proxy.storage = proxy.resources.enter_context(socket.socket())
            proxy.storage.bind(address)
            proxy.storage.listen()
            proxy.storage.settimeout(5)
            proxy.exchange()

    def test_half_close_can_still_receive_slow_response(self):
        packet = request()
        with Proxy() as proxy, proxy.client() as client:
            client.sendall(packet)
            client.shutdown(socket.SHUT_WR)
            with proxy.peer() as peer:
                receive(peer, packet)
                time.sleep(2.1)
                peer.sendall(response())
                receive(client, response())
                eof(peer)

    def test_opaque_response_streams_before_terminator(self):
        packet = request()
        with Proxy() as proxy, proxy.client() as client:
            client.sendall(packet)
            with proxy.peer() as peer:
                receive(peer, packet)
                for block in (b"raw-bytes", b"a", b"bc"):
                    peer.sendall(block)
                    receive(client, block)
                split_send(peer, END, (1, 2, 3))
                receive(client, END)


class ProcessMemoryCounters(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("page_faults", wintypes.DWORD)] + [
        (name, ctypes.c_size_t) for name in ("peak_ws", "ws", "peak_paged", "paged",
                                             "peak_nonpaged", "nonpaged", "pagefile",
                                             "peak_pagefile", "private")]


def tcp_states(pid):
    # IPv4 owner-PID table. Each row contains six DWORDs, with state first and PID last.
    size = wintypes.DWORD()
    table = None
    while True:
        status = ctypes.windll.iphlpapi.GetExtendedTcpTable(table, ctypes.byref(size), False,
                                                            socket.AF_INET, 5, 0)
        if status == 0:
            break
        if status != 122:  # ERROR_INSUFFICIENT_BUFFER
            raise ctypes.WinError(status)
        table = ctypes.create_string_buffer(size.value)
    count, = struct.unpack_from("<I", table)
    rows = struct.iter_unpack("<6I", table.raw[4:4 + 24 * count])
    return [row[0] for row in rows if row[-1] == pid]


def checkpoint(proxy, sessions):
    proxy.exchange("snapshot")
    time.sleep(0.3)
    jobs, finished, retained = map(int, next(line for line in reversed(proxy.logs().splitlines())
                                            if line.startswith("SNAP ")).split()[1:])
    handle = wintypes.HANDLE(int(proxy.process._handle))
    memory = ProcessMemoryCounters()
    memory.cb = ctypes.sizeof(memory)
    handles = wintypes.DWORD()
    if not ctypes.windll.psapi.GetProcessMemoryInfo(handle, ctypes.byref(memory), memory.cb):
        raise ctypes.WinError()
    if not ctypes.windll.kernel32.GetProcessHandleCount(handle, ctypes.byref(handles)):
        raise ctypes.WinError()
    states = tcp_states(proxy.process.pid)
    established, close_wait = states.count(5), states.count(8)
    print(f"{sessions:5d}  {memory.private / 2**20:8.2f}  {memory.ws / 2**20:8.2f}"
          f"  {handles.value:7d}  {jobs:4d}  {finished:8d}  {retained:8d}"
          f"  {established:5d}  {close_wait:10d}", flush=True)
    if finished or retained:
        raise AssertionError("finished jobs or client sockets retained by the task manager")
    if (established, close_wait) != (2, 0):
        raise AssertionError("expected only the two TCP legs of the active control session")
    return memory.private, handles.value, jobs


def disconnect_cycle(proxy, number, packet):
    if number % 4 == 0:
        proxy.exchange()
        return
    with proxy.client() as client:
        if number % 4 == 1:
            # An incomplete checked request never reaches the storage.
            client.sendall(packet[:-12])
        elif number % 4 == 2:
            client.sendall(packet)
            with proxy.peer() as peer:
                receive(peer, packet)
                peer.sendall(response()[:-4])
                abort(peer)
                # A reset may discard bytes already sent by the mock storage.
                try:
                    while client.recv(4096):
                        pass
                except ConnectionResetError:
                    pass
        else:
            abort(client)


def memory_test():
    if os.name != "nt":
        raise SystemExit("--memory requires Windows process counters")
    results = []
    packet = request()
    with Proxy(writable_temp=False) as proxy, proxy.client() as active:
        active.sendall(packet)
        with proxy.peer() as peer:
            receive(peer, packet)
            print("count   private MiB    WS MiB  handles  jobs  finished   sockets  estab  close_wait")
            for batch in range(1, 9):
                for number in range(400):
                    disconnect_cycle(proxy, number, packet)
                for upload in range(8):
                    proxy.interrupt_large_request(reset=upload % 2 == 1)
                results.append(checkpoint(proxy, batch * 400))
            # The same storage session is still usable after all reconnects.
            peer.sendall(response())
            receive(active, response())
        proxy.exchange()
    # Warm up the managed heap and the connection workers for two batches.
    assert_stable_resources(results[1], results[-1])


def assert_stable_resources(baseline, last):
    if last[0] > baseline[0] + 8 * 2**20 or last[1] > baseline[1] + 12 or last[2] > baseline[2] + 2:
        raise AssertionError("process resources grew beyond their post-warm-up range")


def disconnect_burst(proxy, executor, limit, fragment):
    with contextlib.ExitStack() as clients:
        pending = [executor.submit(proxy.client) for _ in range(limit - 1)]
        occupied = [clients.enter_context(future.result(timeout=8)) for future in pending]
        for client in occupied:
            client.sendall(fragment)
        # One control session plus the occupied clients hold every worker.
        with socket.create_connection(("127.0.0.1", proxy.port), 5) as queued:
            queued.settimeout(0.06)
            try:
                queued.recv(1)
            except socket.timeout:
                pass
            else:
                raise AssertionError("accepted a connection above the worker limit")
            occupied.pop().close()
            queued.settimeout(5)
            receive(queued, HELLO)
            queued.sendall(fragment)
        for client in occupied[1::2]:
            abort(client)


def parallel_memory_test():
    if os.name != "nt":
        raise SystemExit("--parallel-memory requires Windows process counters")
    limit = 24
    packet = request()
    results = []
    with Proxy(env={"oproxy_workers": str(limit)}, writable_temp=False) as proxy, proxy.client() as active:
        active.sendall(packet)
        with proxy.peer() as peer, ThreadPoolExecutor(max_workers=limit) as executor:
            receive(peer, packet)
            print("count   private MiB    WS MiB  handles  jobs  finished   sockets  estab  close_wait")
            for batch in range(1, 201):
                disconnect_burst(proxy, executor, limit, packet[:-32])
                if batch == 34 or batch % 25 == 0 and batch >= 50:
                    sample = checkpoint(proxy, batch * limit)
                    if sample[2] != limit:
                        raise AssertionError("worker pool changed size after reaching the limit")
                    results.append(sample)
            peer.sendall(response())
            receive(active, response())
        proxy.exchange()
    # The first post-warm-up sample follows 816 connections, the last follows 4,800.
    assert_stable_resources(results[0], results[-1])


if __name__ == "__main__":
    if sys.argv[1:] == ["--memory"]:
        memory_test()
    elif sys.argv[1:] == ["--parallel-memory"]:
        parallel_memory_test()
    else:
        unittest.main()
