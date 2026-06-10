"""Unit tests for the CAN transport abstraction layer + ISO-TP stack.

Tests run entirely in-process with mocked backends — no hardware, vcan, or root required.

Run:  cd /opt/data/cancat && python -m unittest tests.test_transport -v
       or:   .venv/bin/python -m pytest tests/test_transport.py -v
"""
import importlib.util
import os
import struct
import threading
import time
import unittest
from unittest import mock


# ---------------------------------------------------------------------------
# Import transport module directly, bypassing cancatlib/__init__.py which pulls in
# heavy deps (pyserial) not needed for these tests.
# ---------------------------------------------------------------------------
_transport_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "cancatlib", "transport.py"
)
_spec = importlib.util.spec_from_file_location("transport", _transport_path)
_transport_mod = importlib.util.module_from_spec(_spec)
assert _spec is not None and _spec.loader is not None, "bad spec"
_spec.loader.exec_module(_transport_mod)

Transport = _transport_mod.Transport
SerialTransport = _transport_mod.SerialTransport
SocketcanTransport = _transport_mod.SocketcanTransport


# Import isoip_stack module directly
_isotp_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "cancatlib", "isotp_stack.py"
)
_isotp_spec = importlib.util.spec_from_file_location("isotp_stack", _isotp_path)
_isotp_mod = importlib.util.module_from_spec(_isotp_spec)
assert _isotp_spec is not None and _isotp_spec.loader is not None, "bad isotp spec"
_isotp_spec.loader.exec_module(_isotp_mod)

IsoTpStack = _isotp_mod.IsoTpStack


# =====================================================================
#  Abstract base class tests
# =====================================================================


class TestAbstractBase(unittest.TestCase):

    def test_open_raises(self):
        with self.assertRaises(NotImplementedError):
            Transport().open()

    def test_send_raw_can_raises(self):
        with self.assertRaises(NotImplementedError):
            Transport().send_raw_can(0x123, b"")

    def test_recv_raw_can_raises(self):
        with self.assertRaises(NotImplementedError):
            Transport().recv_raw_can()


# =====================================================================
#  SerialTransport tests
# =====================================================================


class TestSerialTransport(unittest.TestCase):

    def setUp(self):
        self.t = SerialTransport("/dev/null")

    def test_recv_returns_enqued_frame(self):
        frame = (0x123, b"\xAA\xBB", False)
        with self.t._lock_cond:
            self.t._can_recv_queue.append(frame)
            self.t._lock_cond.notify()
        result = self.t.recv_raw_can(timeout=0.5)
        self.assertEqual(result, frame)

    def test_recv_returns_none_on_timeout(self):
        result = self.t.recv_raw_can(timeout=0.1)
        self.assertIsNone(result)

    def test_close_with_no_io(self):
        self.t.close()

    def test_xmit_delegates_to_send(self):
        with mock.patch.object(self.t, "send_raw_can") as stub:
            self.t.xmit_raw_can(0x7FF, b"\x12", extflag=True)
            stub.assert_called_once_with(0x7FF, b"\x12", extflag=True)


# =====================================================================
#  Mocked python-can bus for SocketcanTransport tests
# =====================================================================

class FakeCanMessage:
    """Minimal fake can.Message for testing."""
    def __init__(self, arbitration_id=0, data=b"", is_extended_id=False):
        self.arbitration_id = arbitration_id
        self.data = bytearray(data) if isinstance(data, bytes) else list(data)
        self.is_extended_id = is_extended_id
        self.dlc = len(self.data)

    def __bytes__(self):
        return bytes(self.data)


class FakeCanBus:
    """Fake can.Bus with send/recv for in-process testing."""
    
    _send_queue = []   # fake rx frames injected from outside
    _sent_frames = []  # record of sent frames for assertions
    
    def __init__(self, channel="can0", bustype="socketcan", bitrate=500000):
        self.channel = channel
        self.bustype = bustype
        self.bitrate = bitrate
        self._alive = True

    def send(self, msg):
        if not self._alive:
            raise RuntimeError("Bus shut down")
        FakeCanBus._sent_frames.append(msg)

    def recv(self, timeout=1.0):
        deadline = time.time() + timeout
        while self._alive:
            try:
                return FakeCanBus._send_queue.pop(0)
            except IndexError:
                if time.time() >= deadline:
                    return None
                time.sleep(0.01)

    def shutdown(self):
        self._alive = False


# Global mock replacement for the `can` module
_can_mock = mock.MagicMock()
_can_mock.Bus = FakeCanBus
_can_mock.Message = FakeCanMessage


def _patch_can():
    """Insert fake 'can' into sys.modules and patch transport module attr."""
    import sys
    old_mod = sys.modules.get("can")
    sys.modules["can"] = _can_mock
    
    # Also patch on the transport module in case it cached `can` as an attribute
    patch_obj = mock.patch.object(_transport_mod, "can", new=_can_mock, create=True)
    return old_mod, patch_obj


def _unpatch_can(old_mod):
    """Restore original sys.modules['can'] state."""
    import sys
    if old_mod is None:
        sys.modules.pop("can", None)
    else:
        sys.modules["can"] = old_mod


class TestSocketcanTransport(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls._old_can, cls._patch_obj = _patch_can()
        cls._patch_obj.start()

    @classmethod
    def tearDownClass(cls):
        cls._patch_obj.stop()
        _unpatch_can(cls._old_can)

    def setUp(self):
        self.t = SocketcanTransport(channel="can0", bitrate=500000)
        FakeCanBus._sent_frames.clear()
        FakeCanBus._send_queue.clear()
        _can_mock.reset_mock()

    # ------------------------------------------------------------------
    #  open / close
    # ------------------------------------------------------------------

    def test_open_starts_bus_and_thread(self):
        self.t.open()
        time.sleep(0.05)
        self.assertIsNotNone(self.t._bus)
        self.assertTrue(self.t._running)
        self.assertIsNotNone(self.t._rx_thread)
        self.t.close()

    def test_close_stops_and_shuts_down(self):
        self.t.open()
        time.sleep(0.05)
        self.t.close()
        self.assertFalse(self.t._running)
        self.assertIsNone(self.t._bus)

    # ------------------------------------------------------------------
    #  send_raw_can
    # ------------------------------------------------------------------

    def test_send_pads_data_to_8_bytes(self):
        self.t.open()
        try:
            self.t.send_raw_can(0x123, b"\x01\x02")
            sent = FakeCanBus._sent_frames[-1]
            self.assertEqual(len(sent.data), 8)
            self.assertEqual(bytes(sent.data[:2]), b"\x01\x02")
        finally:
            self.t.close()

    def test_send_forwards_arbid_and_extflag(self):
        self.t.open()
        try:
            self.t.send_raw_can(0x7FF, b"\xFF", extflag=True)
            sent = FakeCanBus._sent_frames[-1]
            self.assertEqual(sent.arbitration_id, 0x7FF)
            self.assertTrue(sent.is_extended_id)
        finally:
            self.t.close()

    def test_send_calls_bus_send(self):
        mock_bus_ref = [None]
        
        # Monkey-patch the bus after open
        self.t.open()
        try:
            self.t.send_raw_can(0x100, b"\xAA")
            self.assertEqual(len(FakeCanBus._sent_frames), 1)
        finally:
            self.t.close()

    def test_send_raises_when_not_open(self):
        with self.assertRaises(RuntimeError):
            self.t.send_raw_can(0x1, b"")

    # ------------------------------------------------------------------
    #  recv_raw_can
    # ------------------------------------------------------------------

    def test_recv_returns_enqueued_frame(self):
        mock_bus = mock.MagicMock()
        mock_bus.recv.return_value = None
        _can_mock.Bus.return_value = mock_bus
        
        self.t.open()
        time.sleep(0.02)
        
        with self.t._lock_cond:
            self.t._recv_queue.append((0x456, b"\xDE\xAD", False))
            self.t._lock_cond.notify()
        
        result = self.t.recv_raw_can(timeout=1.0)
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 3)
        self.t.close()

    def test_recv_returns_none_on_timeout(self):
        mock_bus = mock.MagicMock()
        mock_bus.recv.return_value = None
        _can_mock.Bus.return_value = mock_bus
        
        self.t.open()
        time.sleep(0.12)  # wait for rx poll cycle to drain
        with self.t._lock_cond:
            self.t._recv_queue.clear()
        
        result = self.t.recv_raw_can(timeout=0.1)
        self.assertIsNone(result)
        self.t.close()


# =====================================================================
#  IsoTpStack tests
# =====================================================================

class MockTransportForIsoTP:
    """Mock transport for IsoTpStack testing — records sends, injects receives."""
    
    def __init__(self):
        self._send_log = []      # list of (arbid, data_bytes, extflag)
        self._recv_queue = []    # frames to be returned by recv_raw_can
    
    def send_raw_can(self, arbid, data, extflag=False):
        self._send_log.append((arbid, data, extflag))

    def recv_raw_can(self, timeout=1.0):
        if not self._recv_queue:
            # Block briefly then return None (timeout behavior)
            time.sleep(min(timeout, 0.1))
            return None
        return self._recv_queue.pop(0)

    def inject_recv(self, frame_tuple):
        """Prepend a frame to the recv queue so next recv_raw_can returns it."""
        self._recv_queue.insert(0, frame_tuple)


class TestIsoTpStack(unittest.TestCase):

    def setUp(self):
        self.t = MockTransportForIsoTP()
        self.stack = IsoTpStack(self.t)

    # ------------------------------------------------------------------
    #  Single Frame send (<=6 bytes payload)
    # ------------------------------------------------------------------

    def test_send_single_frame(self):
        data = b"\x10\x01"  # UDS diagnostic request example
        result = self.stack.send(0x7DF, data, extflag=False)
        
        self.assertTrue(result)
        self.assertEqual(len(self.t._send_log), 1)
        arbid, frame_data, _ = self.t._send_log[0]
        self.assertEqual(arbid, 0x7DF)
        # Single Frame: PCI byte + data -> [0x02, 0x10, 0x01]
        self.assertEqual(frame_data[0], 0x02)  # type=SF (0x00), len=2
        self.assertEqual(bytes(frame_data[1:]), data)

    def test_send_single_frame_max(self):
        data = b"\x10\x01\x22\xF1\x90\x00"  # exactly 6 bytes -> single frame
        result = self.stack.send(0x7DF, data, extflag=False)
        
        self.assertTrue(result)
        arbid, frame_data, _ = self.t._send_log[0]
        self.assertEqual(frame_data[0], 0x06)  # SF type + length=6

    # ------------------------------------------------------------------
    #  Multi-frame send (>6 bytes payload)
    # ------------------------------------------------------------------

    def test_send_multiframe_sends_ff(self):
        data = b"\x10\x01" + b"\x48" * 20  # >6 bytes, triggers multi-frame
        total_len = len(data)
        
        # Inject Flow Control responses so the stack can proceed with CFs
        for _ in range(total_len // 7 + 1):
            fc_frame = (0x7E8, struct.pack("BBB", 0x30, 0x00, 0x00), False)
            self.t.inject_recv(fc_frame)
        
        result = self.stack.send(0x7DF, data, extflag=False)
        self.assertTrue(result)
        self.assertGreater(len(self.t._send_log), 1)
        
        # Verify First Frame header format: [0x10, total_len_hi, total_len_lo, data...]
        ff = self.t._send_log[0][1]
        self.assertEqual((ff[0] & 0xF0) >> 4, 0x1)  # FF type

    def test_send_multiframe_handles_overflow_error(self):
        data = b"\x10\x01" + b"\x48" * 20
        
        # Inject overflow error FC as the first response so tx aborts after FF
        fc_error = (0x7E8, struct.pack("BBB", 0x32, 0x00, 0x00), False)
        self.t.inject_recv(fc_error)
        
        result = self.stack.send(0x7DF, data, extflag=False)
        # Stack should return False on overflow error
        self.assertFalse(result)

    # ------------------------------------------------------------------
    #  Single Frame receive
    # ------------------------------------------------------------------

    def test_receive_single_frame(self):
        ff_data = struct.pack("B", 0x03) + b"\x51\x01\x40"  # SF, len=3
        frame_tuple = (0x7E8, ff_data.rstrip(b'\x00')[:4], False)
        self.t.inject_recv(frame_tuple)
        
        result = self.stack.receive(timeout=1.0)
        self.assertEqual(result, b"\x51\x01\x40")

    # ------------------------------------------------------------------
    #  Multi-frame receive
    # ------------------------------------------------------------------

    def test_receive_multiframe(self):
        total_len = 20
        data_payload = os.urandom(total_len)
        
        # First Frame: [0x10, len_hi, len_lo, <first 6 bytes>]
        ff_pci = struct.pack("!BH", 0x10, total_len)
        ff_frame = (0x7E8, ff_pci + data_payload[:6], False)
        
        # Consecutive Frames: [SN | 0xF0, <up to 7 bytes>]
        # Stack expects first CF SN=0 (line 135 in isotp_stack.py)
        cf_frames = []
        sn = 0
        offset = 6
        while offset < total_len:
            chunk = data_payload[offset:offset + 7]
            cf_frame = (0x7E8, struct.pack("B", (sn & 0xF) | 0x30) + chunk, False)
            cf_frames.append(cf_frame)
            sn = (sn + 1) & 0xF
            offset += 7
        
        # Mock transport: inject_recv() uses insert(0), recv_raw_can() uses pop(0).
        # To get FIFO output [FF, CF1, CF2], queue must be [FF, CF1, CF2].
        # Achieve with: inject reverse-CFs first (so earliest CF ends up at front), then FF last.
        for cf in reversed(cf_frames):     # cf_frames is [CF1, CF2,...] → reversed puts them in right order after prepends
            self.t.inject_recv(cf)
        self.t.inject_recv(ff_frame)       # injected last = pops first from index 0
        
        result = self.stack.receive(timeout=3.0)
        self.assertEqual(result, data_payload[:total_len])

    # ------------------------------------------------------------------
    #  Receive timeout
    # ------------------------------------------------------------------

    def test_receive_timeout(self):
        # No frames injected — should return None
        result = self.stack.receive(timeout=0.1)
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
