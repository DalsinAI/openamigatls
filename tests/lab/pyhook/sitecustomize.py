"""OpenTLS's Amiga lab only (tests/lab/lab_amiga.sh): gives the lab's
Amiga a way to the test servers on this machine's loopback. OpenSocket
lets the guest's 127.0.0.1 reach the instance's own listeners only; this
adds entries to that table for the ports in OPENTLS_LAB_PORTS
("29443-29459" or "guest:host,..."), each to the same port on 127.0.0.1.
It is loaded through PYTHONPATH, which lab_instance.py's --env passes to the
lab's host and bridge only; the deployed files are not changed. Nothing
else in the network policy changes.
MIT licensed and free. Copyright (c) 2026 Dalsin Limited."""
import importlib.abc
import importlib.machinery
import os
import sys

MAP = {}
for part in os.environ.get("OPENTLS_LAB_PORTS", "").split(","):
    part = part.strip()
    if ":" in part:
        g, h = part.split(":", 1)
        MAP[int(g)] = int(h)
    elif "-" in part:
        a, b = part.split("-", 1)
        for p in range(int(a), int(b) + 1):
            MAP[p] = p
    elif part:
        MAP[int(part)] = int(part)


def _patch(hs):
    init, reset = hs.HostSocket.__init__, hs.HostSocket.reset

    def add(self):
        for g, h in MAP.items():
            self.listeners[(hs.SOCK_STREAM, g)] = h

    def new_init(self, *a, **k):
        init(self, *a, **k)
        add(self)

    def new_reset(self):
        reset(self)
        add(self)

    hs.HostSocket.__init__, hs.HostSocket.reset = new_init, new_reset


class _Finder(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path, target=None):
        if name != "hostsocket":
            return None
        sys.meta_path.remove(self)
        spec = importlib.machinery.PathFinder.find_spec(name, path)
        if spec is None or spec.loader is None:
            return spec
        run = spec.loader.exec_module

        def exec_module(module):
            run(module)
            _patch(module)

        spec.loader.exec_module = exec_module
        return spec


if MAP:
    sys.meta_path.insert(0, _Finder())
