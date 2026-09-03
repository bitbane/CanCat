"""CAN transport abstraction layer for CanCat.

Provides a common interface for serial and socketcan backends so that
higher-level CAN methods (CanInterface) can work identically regardless of
the underlying physical medium.  No existing serial behaviour is changed.
"""
import select
import struct
import sys
import threading


class Transport(object):
    """Abstract base class for CAN communication."""

    def open(self) -> None:
        raise NotImplementedError("Transport.open() must be overridden")

    def close(self) -> None:
        raise NotImplementedError("Transport.close() must be overridden")

    # -- low-level frame I/O ------------------------------------------

    def send_raw_can(self, arbid: int, data: bytes, extflag: bool = False):
        """Send a single raw CAN frame (max 8-byte payload)."""
        raise NotImplementedError

    def recv_raw_can(self, timeout: float = 1.0):
        """Block up to ``timeout`` seconds for the next CAN frame.

        Returns ``(arbid, data_bytes, extflag)`` or ``None`` on timeout.
        """
        raise NotImplementedError

    # -- convenience --------------------------------------------------

    def xmit_raw_can(self, arbid: int, data: bytes, extflag: bool = False):
        """Send-and-return variant."""
        return self.send_raw_can(arbid, data, extflag=extflag)

# =====================================================================
#  SerialTransport -- thin wrapper around existing CanInterface serial code
# =====================================================================

class SerialTransport(Transport):
    """Transport over CanCat custom serial binary protocol.

    The actual framing logic (_send, _rxtx receiver thread) is kept inside
    :class:`CanInterface` to avoid any regression risk.  This class just
    provides a consistent interface and delegates CAN reads/writes to the
    parent CanInterface instance via its public serial methods.
    """

    def __init__(self, port: str, baud: int = 4000000):
        self.port = port
        self._baud = baud
        self._io = None               # serial.Serial instance -- set by _reconnect()
        self._can_recv_queue = []     # list of (arbid, data_bytes) tuples from rx thread
        self._lock_cond = threading.Condition()

    def open(self):
        """Opened implicitly by CanInterface._reconnect()."""
        pass

    def close(self):
        if hasattr(self, "_io") and self._io:
            try:
                self._io.close()
            except Exception:
                pass
            finally:
                self._io = None

    # -- frame I/O ----------------------------------------------------

    def send_raw_can(self, arbid: int, data: bytes, extflag: bool = False):
        """Enqueue a raw CAN frame for the background serial sender."""
        raise NotImplementedError("Wired to CanInterface._send() in later phase")

    def recv_raw_can(self, timeout: float = 1.0):
        """Wait for next CAN frame from the rx thread queue."""
        with self._lock_cond:
            if not self._can_recv_queue:
                ready = self._lock_cond.wait(timeout=timeout)
            if self._can_recv_queue:
                return self._can_recv_queue.pop(0)
            return None

# =====================================================================
#  SocketCANTransport -- direct Linux SocketCAN via python-can / raw sockets
# =====================================================================

class SocketcanTransport(Transport):
    """Direct Linux SocketCAN transport.

    Uses ``python-can`` as the backend — either the native linux_socketcan
    bus or a raw BSD socket.  ISO-TP flow control is handled in the Python
    layer (via :class:`IsoTpStack`) since SocketCAN has no firmware to do it.
    """

    def __init__(self, channel: str = "can0", bitrate: int = 500000):
        self.channel = channel
        self._bitrate = bitrate
        self._bus = None              # can.Bus instance
        self._recv_queue = []         # list of (arbid, data_bytes, extflag)
        self._lock_cond = threading.Condition()
        self._rx_thread = None
        self._running = False

    def open(self):
        """Start the SocketCAN bus and background rx thread."""
        import can  # python-can
        self._bus = can.Bus(channel=self.channel, bustype="socketcan", bitrate=self._bitrate)
        self._running = True
        self._rx_thread = threading.Thread(target=self._rx_loop, daemon=True)
        self._rx_thread.start()

    def close(self):
        """Stop rx thread and shut down bus."""
        self._running = False
        if self._bus is not None:
            try:
                self._bus.shutdown()
            except Exception:
                pass
            finally:
                self._bus = None

    # -- frame I/O ----------------------------------------------------

    def send_raw_can(self, arbid: int, data: bytes, extflag: bool = False):
        """Send a single CAN frame on the SocketCAN bus."""
        if self._bus is None:
            raise RuntimeError("Bus not opened (did you forget transport.open()?)")
        padded = bytes(list(data) + [0] * (8 - len(data)))[:8]
        can_msg = can.Message(
            arbitration_id=arbid,
            data=padded,
            is_extended_id=extflag,
        )
        self._bus.send(can_msg)

    def recv_raw_can(self, timeout: float = 1.0):
        """Wait for next (arbid, data_bytes, extflag) from rx queue."""
        with self._lock_cond:
            if not self._recv_queue:
                ready = self._lock_cond.wait(timeout=timeout)
            if self._recv_queue:
                return self._recv_queue.pop(0)
            return None

    # -- background receiver ------------------------------------------

    def _rx_loop(self):
        """Background thread: read from SocketCAN bus and enqueue frames."""
        while self._running:
            try:
                frame = self._bus.recv(timeout=0.5)  # non-blocking-ish poll
                if frame is not None:
                    raw_data = bytes(frame.data[:frame.dlc])
                    entry = (frame.arbitration_id, raw_data, frame.is_extended_id)
                    with self._lock_cond:
                        self._recv_queue.append(entry)
                        self._lock_cond.notify()
            except Exception as e:
                if self._running:
                    import sys
                    print(f"SocketCAN rx error: {e}", file=sys.stderr, flush=True)
