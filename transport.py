"""
Transport abstraction for D'Arcraw.

Production transport speaks I2P SAM v3, so every node is an I2P destination (b32)
and all RPC rides inside I2P. This module defines the interface plus an in-memory
transport for local testing. Swapping to I2P means implementing Transport against
a SAM session; nothing above this layer changes.
"""
from abc import ABC, abstractmethod


class Transport(ABC):
    @property
    @abstractmethod
    def address(self) -> str:
        """This node's destination identifier (a b32 under I2P)."""

    @abstractmethod
    def send(self, dest: str, msg: bytes) -> bytes:
        """Send a request to dest, return the response bytes."""

    @abstractmethod
    def serve(self, handler) -> None:
        """Register handler(src_address, msg_bytes) -> response_bytes."""


class InMemoryNetwork:
    """A local message bus so several nodes can talk in one process, for tests."""

    def __init__(self):
        self._nodes = {}

    def register(self, addr, handler):
        self._nodes[addr] = handler

    def send(self, src, dest, msg):
        handler = self._nodes.get(dest)
        if handler is None:
            raise ConnectionError(dest)
        return handler(src, msg)


class InMemoryTransport(Transport):
    def __init__(self, net: InMemoryNetwork, address: str):
        self._net = net
        self._addr = address

    @property
    def address(self) -> str:
        return self._addr

    def send(self, dest: str, msg: bytes) -> bytes:
        return self._net.send(self._addr, dest, msg)

    def serve(self, handler) -> None:
        self._net.register(self._addr, handler)
