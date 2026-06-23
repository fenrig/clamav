#!/usr/bin/env python3
# Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

import os
import socket
import subprocess
import threading
import time
import unittest

from pathlib import Path

import testcase


def sockets_available():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM):
            return True
    except OSError:
        return False


SOCKETS_AVAILABLE = sockets_available()


class FakeClamd:
    def __init__(self):
        self.host = "127.0.0.1"
        self.port = 0
        self.commands = []
        self._stop = threading.Event()
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._serve)

    def __enter__(self):
        self._thread.start()
        if not self._ready.wait(5):
            raise RuntimeError("fake clamd socket did not start")
        return self

    def __exit__(self, exc_type, exc, tb):
        self._stop.set()
        try:
            with socket.create_connection((self.host, self.port), timeout=1):
                pass
        except OSError:
            pass
        self._thread.join(5)

    def wait_for_scans(self, count, timeout=5):
        deadline = time.time() + timeout
        while time.time() < deadline:
            scans = [cmd for cmd in self.commands if cmd.startswith("zCONTSCAN ")]
            if len(scans) >= count:
                return scans
            time.sleep(0.05)
        return [cmd for cmd in self.commands if cmd.startswith("zCONTSCAN ")]

    def _serve(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.host, 0))
            self.port = server.getsockname()[1]
            server.listen(16)
            server.settimeout(0.2)
            self._ready.set()

            while not self._stop.is_set():
                try:
                    conn, _ = server.accept()
                except socket.timeout:
                    continue

                with conn:
                    data = bytearray()
                    while True:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        data.extend(chunk)
                        if b"\0" in chunk:
                            break

                    if not data:
                        continue

                    command = bytes(data).split(b"\0", 1)[0].decode("utf-8", "replace")
                    self.commands.append(command)

                    if command.startswith("zCONTSCAN "):
                        pathname = command[len("zCONTSCAN "):]
                        conn.sendall(f"{pathname}: OK\0".encode())


class TC(testcase.TestCase):
    def _write_config(self, download_dir, port, ignore_extensions=None, extra_lines=""):
        if ignore_extensions is None:
            ignore_extensions = [".part", ".crdownload", ".tmp"]

        config = self.path_tmp / "clamonacc-download.conf"
        config.write_text(
            "\n".join(
                [
                    "TCPAddr 127.0.0.1",
                    f"TCPSocket {port}",
                    "OnAccessCurlTimeout 1000",
                    "OnAccessMaxThreads 2",
                    f"OnAccessDownloadPath {download_dir}",
                    *[f"OnAccessDownloadIgnoreExtension {ext}" for ext in ignore_extensions],
                    "OnAccessDownloadScanOnFinalize yes",
                    extra_lines,
                ]
            )
        )
        return config

    def _start_clamonacc(self, config, log_file):
        proc = subprocess.Popen(
            [str(self.clamonacc), "-F", "--log", str(log_file), "-c", str(config)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        deadline = time.time() + 5
        while time.time() < deadline:
            if proc.poll() is not None:
                stdout, stderr = proc.communicate(timeout=1)
                raise AssertionError(f"clamonacc exited early: {proc.returncode}\n{stdout}\n{stderr}")
            if log_file.exists() and "watching" in log_file.read_text(errors="replace"):
                return proc
            time.sleep(0.05)

        proc.terminate()
        proc.wait(timeout=5)
        raise AssertionError("clamonacc did not start download watcher")

    def _stop_clamonacc(self, proc):
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)

    @unittest.skipIf(os.name == "nt", "download watcher uses Linux inotify")
    @unittest.skipIf(not SOCKETS_AVAILABLE, "socket creation is unavailable")
    def test_ignored_part_close_does_not_scan(self):
        download_dir = self.path_tmp / "downloads-part"
        download_dir.mkdir()
        log_file = self.path_tmp / "clamonacc-part.log"

        with FakeClamd() as clamd:
            config = self._write_config(download_dir, clamd.port)
            proc = self._start_clamonacc(config, log_file)
            try:
                (download_dir / "foo.png.part").write_text("partial")
                scans = clamd.wait_for_scans(1, timeout=1)
                self.assertEqual([], scans)
            finally:
                self._stop_clamonacc(proc)

    @unittest.skipIf(os.name == "nt", "download watcher uses Linux inotify")
    @unittest.skipIf(not SOCKETS_AVAILABLE, "socket creation is unavailable")
    def test_part_rename_to_final_triggers_one_scan(self):
        download_dir = self.path_tmp / "downloads-rename"
        download_dir.mkdir()
        log_file = self.path_tmp / "clamonacc-rename.log"

        with FakeClamd() as clamd:
            config = self._write_config(download_dir, clamd.port)
            proc = self._start_clamonacc(config, log_file)
            try:
                part = download_dir / "foo.png.part"
                final = download_dir / "foo.png"
                part.write_text("final")
                part.rename(final)
                scans = clamd.wait_for_scans(1)
                self.assertEqual(1, len(scans))
                self.assertTrue(scans[0].endswith(str(final)))
            finally:
                self._stop_clamonacc(proc)

    @unittest.skipIf(os.name == "nt", "download watcher uses Linux inotify")
    @unittest.skipIf(not SOCKETS_AVAILABLE, "socket creation is unavailable")
    def test_direct_final_close_triggers_one_scan(self):
        download_dir = self.path_tmp / "downloads-direct"
        download_dir.mkdir()
        log_file = self.path_tmp / "clamonacc-direct.log"

        with FakeClamd() as clamd:
            config = self._write_config(download_dir, clamd.port)
            proc = self._start_clamonacc(config, log_file)
            try:
                final = download_dir / "foo.zip"
                final.write_text("final")
                scans = clamd.wait_for_scans(1)
                self.assertEqual(1, len(scans))
                self.assertTrue(scans[0].endswith(str(final)))
            finally:
                self._stop_clamonacc(proc)

    @unittest.skipIf(os.name == "nt", "download watcher uses Linux inotify")
    @unittest.skipIf(not SOCKETS_AVAILABLE, "socket creation is unavailable")
    def test_multiple_ignored_suffixes_do_not_scan(self):
        download_dir = self.path_tmp / "downloads-suffixes"
        download_dir.mkdir()
        log_file = self.path_tmp / "clamonacc-suffixes.log"

        with FakeClamd() as clamd:
            config = self._write_config(download_dir, clamd.port)
            proc = self._start_clamonacc(config, log_file)
            try:
                (download_dir / "foo.crdownload").write_text("partial")
                (download_dir / "bar.tmp").write_text("partial")
                scans = clamd.wait_for_scans(1, timeout=1)
                self.assertEqual([], scans)
            finally:
                self._stop_clamonacc(proc)

    def test_invalid_download_path_is_rejected(self):
        config = self._write_config(self.path_tmp / "missing", 3310)

        result = self.execute_command(f"{self.clamonacc} -F -c {config}")
        self.assertEqual(2, result.ec)
        self.assertIn("invalid OnAccessDownloadPath", result.err)

    def test_invalid_ignore_extension_is_rejected(self):
        download_dir = self.path_tmp / "downloads-invalid-ext"
        download_dir.mkdir()
        config = self._write_config(download_dir, 3310, ignore_extensions=["part"])

        result = self.execute_command(f"{self.clamonacc} -F -c {config}")
        self.assertEqual(2, result.ec)
        self.assertIn("invalid OnAccessDownloadIgnoreExtension", result.err)


if __name__ == "__main__":
    unittest.main()
