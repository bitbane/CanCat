"""ISO-TP (ISO 15765-2) stack implemented in the Python layer.

Provides multi-frame message assembly/disassembly with flow control for
SocketCAN mode, where the underlying kernel does not handle ISO-TP natively.

Used by CanCat when communicating via SocketCAN to send and receive ECU
messages larger than 8 bytes (UDS diagnostic requests/responses).
"""
from __future__ import print_function
import struct
import sys
import threading
import time


# ---------------------------------------------------------------------------
# ISO-TP constants
# ---------------------------------------------------------------------------

ISO_TP_SA    = 0x00   # Single Frame indicator bit position (bits 7-6)
ISO_TP_FF    = 0x10   # First Frame indicator
ISO_TP_FC    = 0x20   # Flow Control indicator
ISO_TP_CF    = 0x30   # Consecutive Frame indicator
ISO_TP_TS_MASK = 0x0F # Reserved byte / timestamp mask

# Single frame maximum payload (5 bytes type + data)
ISO_TP_SF_MAX_DL = 6

# Flow control status values
ISO_TP_FC_CONTINUE       = 0x00
ISO_TP_FC_WAIT           = 0x01
ISO_TP_FC_OVERFLOW_ERROR = 0x02

# Default flow control parameters
ISO_TP_DS_SEP_DEFAULT    = 0x00   # min. 0 ms between CFs
ISO_TP_BS_DEFAULT        = 0x80   # block size 0 (unlimited)


class IsoTpStack(object):
    """Python-layer ISO-TP stack for SocketCAN transport.

    Handles multi-frame send/receive with flow control negotiation.  Wraps a
    :class:`Transport` instance that provides ``send_raw_can`` and
    ``recv_raw_can`` for single 8-byte CAN frames.
    """

    def __init__(self, transport, rx_id=None, tx_id=None):
        self._transport = transport
        self._rx_id = rx_id or 0x7DF   # standard OBD-UAS receiver
        self._tx_id = tx_id or 0x7E8   # default ECU response address
        self._fc_bs = ISO_TP_BS_DEFAULT
        self._fc_st_min = ISO_TP_DS_SEP_DEFAULT
        self._lock = threading.Lock()

    def send(self, arbid, data, extflag=False):
        """Send a (potentially > 8 byte) ISO-TP message.

        Returns ``True`` on success or ``False`` if the ECU responds with an error.
        """
        total_len = len(data)
        if total_len <= ISO_TP_SF_MAX_DL:
            # -- Single Frame --------------------------------------------------
            header = struct.pack("B", ISO_TP_SA | total_len)
            frame_data = header + data[:total_len]
            self._transport.send_raw_can(arbid, frame_data, extflag=extflag)
            return True

        # -- Multi-Frame: First Frame ------------------------------------------
        ff_header = struct.pack("!BH", ISO_TP_FF, total_len)
        ff_payload = ff_header + data[:6]
        self._transport.send_raw_can(arbid, ff_payload, extflag=extflag)

        # -- Send Consecutive Frames, respecting flow control ------------------
        offset = 6
        block_count = 0
        sn = 1  # sequence number starts at 1 for CF[1]

        while offset < total_len:
            # Wait for next FC before sending more (ECU may send FC)
            resp = self._transport.recv_raw_can(timeout=2.0)

            if resp is not None:
                arbid_r, frame_data, extflag_r = resp
                fc_status = self._parse_flow_control(frame_data)
                if fc_status == ISO_TP_FC_OVERFLOW_ERROR:
                    print("ISO-TP flow control overflow error", file=sys.stderr)
                    return False
                elif fc_status == ISO_TP_FC_WAIT:
                    # Wait before continuing
                    continue

            # Send Consecutive Frame
            cf_header = struct.pack("B", ISO_TP_CF | (sn & 0x0F))
            cf_payload = cf_header + data[offset:offset + 7]
            self._transport.send_raw_can(arbid, cf_payload, extflag=extflag)

            offset += 7
            sn = (sn + 1) & 0x0F
            block_count += 1

            # Block size check -- must wait for FC if BS is set
            if self._fc_bs != 0 and block_count >= self._fc_bs:
                block_count = 0

            # Inter-frame delay (STmin conversion)
            st_min_us = self._st_min_to_us(self._fc_st_min or 0)
            if st_min_us > 0:
                time.sleep(st_min_us / 1e6)

        return True

    def receive(self, timeout=5.0):
        """Wait for and assemble an incoming ISO-TP message.

        Returns ``None`` on timeout. Otherwise returns raw response data bytes.
        """
        first_frame = self._transport.recv_raw_can(timeout=timeout)
        if first_frame is None:
            return None

        arbid, frame_data, extflag = first_frame
        pci_byte = frame_data[0]
        pci_type = (pci_byte & 0xF0) >> 4

        if pci_type == 0x0:
            # -- Single Frame --------------------------------------------------
            length = pci_byte & 0x0F
            return frame_data[1:length + 1]

        elif pci_type == 0x1:
            # -- First Frame (multi-frame) ------------------------------------
            total_length = struct.unpack("!H", frame_data[1:3])[0]
            accumulated = bytearray(frame_data[3:])  # first 6 bytes of data

            sn = 0  # expected sequence number for next CF

            while len(accumulated) < total_length:
                cf_frame = self._transport.recv_raw_can(timeout=2.0)
                if cf_frame is None:
                    break
                _, cf_data, _ = cf_frame
                cf_sn = cf_data[0] & 0x0F

                if cf_sn != sn:
                    print("ISO-TP consecutive frame sequence error", file=sys.stderr)
                    return None

                accumulated += cf_data[1:]   # append payload bytes (7 max per CF)
                sn = (sn + 1) & 0x0F

            else:
                return bytes(accumulated[:total_length])

        elif pci_type == 0x3:
            # -- Response to a request the ECU sent to us; send FC --------------
            self._send_flow_control()

    def _parse_flow_control(self, frame_data):
        """Parse and extract flow control parameters.

        Returns the status code (CONTINUE/WAIT/OVERFLOW_ERROR).
        """
        try:
            status_code = frame_data[0] & 0x0F
            bs = frame_data[1]
            st_min_raw = frame_data[2]
        except IndexError:
            return ISO_TP_FC_OVERFLOW_ERROR

        self._fc_bs = bs
        if st_min_raw <= 0x7F:
            self._fc_st_min = st_min_raw    # ms value
        elif st_min_raw >= 0xF1 and st_min_raw <= 0xF9:
            self._fc_st_min = st_min_raw - 0xF1 + 100   # map to centiseconds

        return status_code

    def _st_min_to_us(self, raw):
        """Convert STmin byte value to microseconds."""
        if raw == 0:
            return 0
        elif raw <= 0x7F:
            return int(raw * 1e3)      # ms -> us
        elif raw >= 0xF1 and raw <= 0xF9:
            centiseconds = (raw - 0xF1 + 100)
            return int(centiseconds * 10e3)   # cs to us

    def _send_flow_control(self):
        """Send a Flow Control message back to the ECU."""
        fc_frame = struct.pack("BBB",
                               ISO_TP_FC | ISO_TP_FC_CONTINUE,
                               self._fc_bs,                 # block size
                               self._fc_st_min              # STmin
                              )[:8]  # pad to 8 bytes for CAN frame
