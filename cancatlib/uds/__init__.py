from __future__ import print_function
from builtins import input

import sys
import time
import struct
import threading
import math

import cancatlib.iso_tp as cisotp

# In 11-bit CAN, an OBD2 tester typically sends requests with an ID of 7DF, and
# can accept response messages on IDs 7E8 to 7EF, requests to a specific ECU can
# be sent from ID 7E0 to 7E7.  So the non-OBD2 range normally ends at 7D7,
# although I can't find a specific "standard" for this.
#
# In 29-bit CAN an OBD2 tester typically sends requests with an ID of 0x18DB33F1
# where 0x18DBxxxx indicates this is an OBD2 message, 0x33 indicates this
# message is for the OBD2 ECU(s), and 0xF1 is the tester.  Normal UDS messages
# use a prefix of 0x18DAxxxx.
# 0xF1 is used as a tester address in normal UDS messaging as well.
ARBID_CONSTS = (
    # extflag = 0, 11bit
    {
        'prefix': 0x700,
        'prefix_mask': 0xF00,
        'resp_offset': 8,  # rxid is normally the txid + 8
        'obd2_broadcast': 0x7DF,
        'obd2_response': 0x7E8,

        # To ensure the entries match between 11 and 29-bit constants
        'destid_mask': None,
        'destid_shift': None,
        'srcid_mask': None,
        'tester': None,
    },
    # extflag = 1, 29bit
    {
        'prefix': 0x18DA0000,
        'prefix_mask': 0xFFFF0000,
        'destid_mask': 0x0000FF00,
        'destid_shift': 8,
        'srcid_mask': 0x000000FF,
        'tester': 0xF1,
        'obd2_broadcast': 0x18DB33F1,
        'obd2_response': 0x18DAF10E,

        # To ensure the entries match between 11 and 29-bit constants
        'resp_offset': None,
    }
)

ISO_14229_DIDS = {
    0xF180: 'bootSoftwareIdentificationDataIdentifier',
    0xF181: 'applicationSoftwareIdentificationDataIdentifier',
    0xF182: 'applicationDataIdentificationDataIdentifier',
    0xF183: 'bootSoftwareFingerprintDataIdentifier',
    0xF184: 'applicationSoftwareFingerprintDataIdentifier',
    0xF185: 'applicationDataFingerprintDataIdentifier',
    0xF186: 'activeDiagnosticSessionDataIdentifier',
    0xF187: 'vehicleManufacturerSparePartNumberDataIdentifier',
    0xF188: 'vehicleManufacturerECUSoftwareNumberDataIdentifier',
    0xF189: 'vehicleManufacturerECUSoftwareVersionNumberDataIdentifier',
    0xF18A: 'systemSupplierIdentifierDataIdentifier',
    0xF18B: 'ECUManufacturingDateDataIdentifier',
    0xF18C: 'ECUSerialNumberDataIdentifier',
    0xF18D: 'supportedFunctionalUnitsDataIdentifier',
    0xF18E: 'vehicleManufacturerKitAssemblyPartNumberDataIdentifier',
    0xF190: 'VINDataIdentifier',
    0xF191: 'vehicleManufacturerECUHardwareNumberDataIdentifier',
    0xF192: 'systemSupplierECUHardwareNumberDataIdentifier',
    0xF193: 'systemSupplierECUHardwareVersionNumberDataIdentifier',
    0xF194: 'systemSupplierECUSoftwareNumberDataIdentifier',
    0xF195: 'systemSupplierECUSoftwareVersionNumberDataIdentifier',
    0xF196: 'exhaustRegulationOrTypeApprovalNumberDataIdentifier',
    0xF197: 'systemNameOrEngineTypeDataIdentifier',
    0xF198: 'repairShopCodeOrTesterSerialNumberDataIdentifier',
    0xF199: 'programmingDateDataIdentifier',
    0xF19A: 'calibrationRepairShopCodeOrCalibrationEquipmentSerialNumberData-',
    0xF19B: 'calibrationDateDataIdentifier',
    0xF19C: 'calibrationEquipmentSoftwareNumberDataIdentifier',
    0xF19D: 'ECUInstallationDateDataIdentifier',
    0xF19E: 'ODXFileDataIdentifier',
    0xF19F: 'entityDataIdentifier',
}

NEG_RESP_CODES = {
    0x10: 'GeneralReject',
    0x11: 'ServiceNotSupported',
    0x12: 'SubFunctionNotSupported',
    0x13: 'IncorrectMesageLengthOrInvalidFormat',
    0x14: 'ResponseTooLong',
    0x21: 'BusyRepeatRequest',
    0x22: 'ConditionsNotCorrect',
    0x24: 'RequestSequenceError',
    0x25: 'NoResponseFromSubnetComponent',
    0x26: 'FailurePreventsExecutionOfRequestedAction',
    0x31: 'RequestOutOfRange',
    0x33: 'SecurityAccessDenied',
    0x35: 'InvalidKey',
    0x36: 'ExceedNumberOfAttempts',
    0x37: 'RequiredTimeDelayNotExpired',
    0x70: 'UploadDownloadNotAccepted',
    0x71: 'TransferDataSuspended',
    0x72: 'GeneralProgrammingFailure',
    0x73: 'WrongBlockSequenceCounter',
    0x78: 'RequestCorrectlyReceived-ResponsePending',
    0x7e: 'SubFunctionNotSupportedInActiveSession',
    0x7f: 'ServiceNotSupportedInActiveSession',
    0x81: 'RpmTooHigh',
    0x82: 'RpmTooLow',
    0x83: 'EngineIsRunning',
    0x84: 'EngineIsNotRunning',
    0x85: 'EngineRunTimeTooLow',
    0x86: 'TemperatureTooHigh',
    0x87: 'TemperatureTooLow',
    0x88: 'VehicleSpeedTooHigh',
    0x89: 'VehicleSpeedTooLow',
    0x8a: 'ThrottlePedalTooHigh',
    0x8b: 'ThrottlePedalTooLow',
    0x8c: 'TransmissionRangeNotInNeutral',
    0x8d: 'TransmissionRangeNotInGear',
    0x8f: 'BrakeSwitchsNotClosed',
    0x90: 'ShifterLeverNotInPark',
    0x91: 'TorqueConverterClutchLocked',
    0x92: 'VoltageTooHigh',
    0x93: 'VoltageTooLow',
}

SVC_DIAGNOSTICS_SESSION_CONTROL = 0x10
SVC_ECU_RESET = 0x11
SVC_CLEAR_DIAGNOSTICS_INFORMATION = 0x14
SVC_READ_DTC_INFORMATION = 0x19
SVC_READ_DATA_BY_IDENTIFIER = 0x22
SVC_READ_MEMORY_BY_ADDRESS = 0x23
SVC_SECURITY_ACCESS = 0x27
SVC_READ_DATA_BY_PERIODIC_IDENTIFIER = 0x2a
SVC_DYNAMICALLY_DEFINE_DATA_IDENTIFIER = 0x2c
SVC_WRITE_DATA_BY_IDENTIFIER = 0x2e
SVC_INPUT_OUTPUT_CONTROL_BY_IDENTIFIER = 0x2f
SVC_ROUTINE_CONTROL = 0x31
SVC_REQUEST_DOWNLOAD = 0x34
SVC_REQUEST_UPLOAD = 0x35
SVC_TRANSFER_DATA = 0x36
SVC_REQUEST_TRANSFER_EXIT = 0x37
SVC_WRITE_MEMORY_BY_ADDRESS = 0x3d
SVC_TESTER_PRESENT = 0x3e
SVC_NEGATIVE_RESPONSE = 0x7f
SVC_CONTROL_DTC_SETTING = 0x85

UDS_SVCS = {v: k for k, v in globals().items() if k.startswith('SVC_')}

POS_RESP_CODES = {(k | 0x40): "OK_" + v.lower() for k, v in UDS_SVCS.items()}
POS_RESP_CODES[0] = 'Success'

NEG_RESP_REPR = {}
for k, v in NEG_RESP_CODES.items():
    NEG_RESP_REPR[k] = 'ERR_' + v

RESP_CODES = {}
RESP_CODES.update(NEG_RESP_REPR)
RESP_CODES.update(POS_RESP_CODES)


class UDSTimeout(Exception):
    pass


class NegativeResponseException(Exception):
    def __init__(self, neg_code, svc, msg):
        self.neg_code = neg_code
        self.msg = msg
        self.svc = svc

    def __repr__(self):
        negresprepr = NEG_RESP_CODES.get(self.neg_code)
        return "NEGATIVE RESPONSE to 0x%x (%s):   ERROR 0x%x: %s   \tmsg: %s" % \
            (self.svc, UDS_SVCS.get(self.svc), self.neg_code, negresprepr, self.msg)

    def __str__(self):
        negresprepr = NEG_RESP_CODES.get(self.neg_code)
        return "NEGATIVE RESPONSE to 0x%x (%s):   ERROR 0x%x: %s   \tmsg: %s" % \
            (self.svc, UDS_SVCS.get(self.svc), self.neg_code, negresprepr, self.msg)


class UDS(object):
    def __init__(self, c, tx_arbid, rx_arbid=None, verbose=True, extflag=0, timeout=3.0):
        self.c = c
        self.t = None
        self.verbose = verbose
        self.extflag = extflag
        self.timeout = timeout

        if rx_arbid is None:
            rx_arbid = tx_arbid + 8  # by UDS spec

        self.tx_arbid = tx_arbid
        self.rx_arbid = rx_arbid

    def xmit_recv(self, data, extflag=0, count=1, service=None):
        msg, idx = self.c.ISOTPxmit_recv(self.tx_arbid, self.rx_arbid, data, extflag, self.timeout, count, service)

        # Process response
        svc = data[0]

        if service is None:
            svc_resp = struct.pack('>B', svc + 0x40)
        elif isinstance(service, int):
            svc_resp = struct.pack('>B', service)
        else:
            svc_resp = service

        while True:
            if msg is None:
                raise UDSTimeout()
            if msg[:len(svc_resp)] == svc_resp:
                if self.verbose:
                    print("Positive Response!")
                break
            else:
                # Some sort of error has occurred
                errcode = msg[2]
                if self.verbose > 1:
                    negresprepr = NEG_RESP_CODES.get(errcode)
                    print(negresprepr + "\n")

                # Don't throw an exception for
                # ResponseCorrectlyReceivedResponsePending
                if errcode == 0x78:
                    # Try again but increment the start index
                    msg, idx = self.c._isotp_get_msg(self.rx_arbid, start_index=idx+1, service=service, timeout=self.timeout)
                else:
                    raise NegativeResponseException(errcode, svc, msg)

        return msg

    def _do_Function(self, func, data=None, subfunc=None, service=None):
        if subfunc is not None:
            omsg = struct.pack('>BB', func, subfunc)
        else:
            omsg = struct.pack('>B', func)

        if data is not None:
            omsg += data

        msg = self.xmit_recv(omsg, extflag=self.extflag, service=service)
        return msg

    def SendTesterPresent(self):
        while self.TesterPresent is True:
            if self.TesterPresentRequestsResponse:
                self.c.CANxmit(self.tx_arbid, b"\x02\x3E\x00\x00\x00\x00\x00\x00", self.extflag)
            else:
                self.c.CANxmit(self.tx_arbid, b"\x02\x3E\x80\x00\x00\x00\x00\x00", self.extflag)
            time.sleep(2.0)

    def StartTesterPresent(self, request_response=True):
        self.TesterPresent = True
        self.TesterPresentRequestsResponse = request_response
        self.t = threading.Thread(target=self.SendTesterPresent)
        self.t.setDaemon(True)
        self.t.start()

    def StopTesterPresent(self):
        self.TesterPresent = False
        if self.t is not None:
            self.t.join(5.0)
            if self.t.is_alive():
                if self.verbose:
                    print("Error killing Tester Present thread")
            self.t = None

    def DiagnosticSessionControl(self, session):
        data = struct.pack('>B', session)
        return self._do_Function(SVC_DIAGNOSTICS_SESSION_CONTROL, data=data, service=0x50)

    def ReadMemoryByAddress(self, address, size):
        data = struct.pack(">IH", address, size)
        return self._do_Function(SVC_READ_MEMORY_BY_ADDRESS, subfunc=0x24, data=data, service=0x63)

    def ReadDID(self, did):
        '''
        Read the Data Identifier specified from the ECU.

        Returns: The response ISO-TP message as a string
        '''
        resp = struct.pack('>BH',SVC_READ_DATA_BY_IDENTIFIER+0x40, did)
        msg = self._do_Function(SVC_READ_DATA_BY_IDENTIFIER, struct.pack('>H', did), service=resp)
        return msg

    def WriteDID(self, did, data):
        '''
        Write the Data Identifier specified from the ECU.

        Returns: The response ISO-TP message as a string
        '''
        resp = struct.pack('>BH',SVC_WRITE_DATA_BY_IDENTIFIER+0x40, did)
        msg = self._do_Function(SVC_WRITE_DATA_BY_IDENTIFIER, struct.pack('>H', did) + data, service=resp)
        return msg

    def RequestDownload(self, addr, data, data_format=0x00, addr_format=0x44):
        '''
        Assumes correct Diagnostics Session and SecurityAccess
        '''
        # Figure out the right address and data length formats. The standard
        # size formats are 1, 2, and 4 but some ECUs use other values
        addr_data = struct.pack('>Q', addr)[8-(addr_format >> 4):]
        addr_len_data = struct.pack('>Q', len(data))[8-(addr_format & 0xF):]

        req_data = b"\x34" + struct.pack('>BB', data_format, addr_format) + addr_data + addr_len_data
        msg = self.xmit_recv(req_data, extflag=self.extflag, service=0x74)

        # Parse the response
        if msg[0] != 0x74:
            print("Error received: {}".format(msg.encode('hex')))
            return msg
        max_txfr_num_bytes = msg[1] >> 4  # number of bytes in the max tranfer length parameter
        max_txfr_len = 0
        for i in range(2, 2 + max_txfr_num_bytes):
            max_txfr_len <<= 8
            max_txfr_len += msg[i]

        # Transfer data
        data_idx = 0
        block_idx = 1
        while data_idx < len(data):
            data_chunk = struct.pack('>B', block_idx) + data[data_idx:data_idx + max_txfr_len - 2]
            msg = self.xmit_recv(b"\x36" + data_chunk, extflag=self.extflag, service=0x76)
            data_idx += max_txfr_len - 2
            block_idx += 1
            if block_idx > 0xff:
                block_idx = 0

            # error checking
            if msg is not None and msg[0] == 0x7f and msg[2] != 0x78:
                print("Error sending data: {}".format(msg.encode('hex')))
                return None
            if msg is None:
                print("Didn't get a response?")
                data_idx -= max_txfr_len - 2
                block_idx -= 1
                if block_idx == 0:
                    block_idx = 0xff

            # TODO: need to figure out how to get 2nd isotp message to verify that this worked

        # Send RequestTransferExit
        self._do_Function(SVC_REQUEST_TRANSFER_EXIT, service=0x77)

    def readMemoryByAddress(self, address, length, lenlen=1, addrlen=4):
        '''
        Work in progress!
        '''
        if lenlen == 1:
            lfmt = "B"
        else:
            lfmt = "H"

        lenlenbyte = (lenlen << 4) | addrlen

        data = struct.pack('<BI' + lfmt, lenlenbyte, address, length)
        msg = self._do_Function(SVC_READ_MEMORY_BY_ADDRESS, data=data, service=0x63)

        return msg

    def writeMemoryByAddress(self, address, data, lenlen=1, addrlen=4):
        '''
        Work in progress!
        '''
        if lenlen == 1:
            lfmt = "B"
        else:
            lfmt = "H"

        lenlenbyte = (lenlen << 4) | addrlen

        data = struct.pack('<BI' + lfmt, lenlenbyte, address, lenlenbyte)

        msg = self._do_Function(SVC_WRITE_MEMORY_BY_ADDRESS, data=data, service=0x7d)

        return msg

    def RequestUpload(self, addr, length, data_format=0x00, addr_format=0x44):
        '''
        Work in progress!
        '''
        # Figure out the right address and data length formats. The standard
        # size formats are 1, 2, and 4 but some ECUs use other values
        addr_data = struct.pack('>Q', addr)[8-(addr_format >> 4):]
        addr_len_data = struct.pack('>Q', length)[8-(addr_format & 0xF):]

        req_data = b"\x35" + struct.pack('>BB', data_format, addr_format) + addr_data + addr_len_data
        msg = self.xmit_recv(req_data, extflag=self.extflag, service=0x75)

        sid, lfmtid, maxnumblocks = struct.unpack('>BBH', msg[:4])

        output = []
        for loop in maxnumblocks:
            msg = self._do_Function(SVC_TRANSFER_DATA, subfunc=loop, service=0x76)
            output.append(msg)

            if len(msg) and msg[0] != 0x76:
                print("FAILURE TO DOWNLOAD ALL.  Returning what we have so far (including error message)")
                return output

        msg = self._do_Function(SVC_REQUEST_TRANSFER_EXIT, service=0x77)
        if len(msg) and msg[0] != 0x77:
            print("FAILURE TO EXIT CLEANLY.  Returning what we received.")

        return output

    def EcuReset(self, rst_type=0x1):
        return self._do_Function(SVC_ECU_RESET, subfunc=rst_type)

    def ClearDiagnosticInformation(self):
        pass

    def ReadDTCInfomation(self):
        pass

    def ReadDataByPeriodicIdentifier(self, pdid):
        pass

    def DynamicallyDefineDataIdentifier(self):
        pass

    def InputOutputControlByIdentifier(self, iodid):
        pass

    def TransferData(self, did):
        pass

    def RequestTransferExit(self):
        pass

    def ControlDTCSetting(self):
        pass

    def RoutineControl(self, action, routine, *args):
        """
        action: 1 for start, 0 for stop
        routine: 2 byte value for which routine to call
        *args: any additional arguments (must already be bytes)
        """
        # Extra data for routine control is initially just the routine, but
        # accepts additional bytes
        data = struct.pack('>H', routine)
        for arg in args:
            data += arg
        return self._do_Function(SVC_ROUTINE_CONTROL, subfunc=action, data=data)

    def ScanDIDs(self, start=0, end=0x10000, delay=0):
        success = []
        try:
            for x in range(start, end):
                try:
                    if self.verbose:
                        sys.stderr.write(' %x ' % x)

                    val = self.ReadDID(x)
                    success.append((x, val))

                except KeyboardInterrupt:
                    raise

                except Exception as e:
                    if self.verbose > 1:
                        print(e)

                time.sleep(delay)

        except KeyboardInterrupt:
            print("Stopping Scan during DID 0x%x " % x)
            return success

        return success

    def SecurityAccess(self, level, secret=""):
        """Send and receive the UDS messages to switch SecurityAccess levels.
            @level = the SecurityAccess level to switch to
            @secret = a SecurityAccess algorithm specific secret used to generate the key
        """
        resp = struct.pack('>BB',SVC_SECURITY_ACCESS+0x40, level)
        msg = self._do_Function(SVC_SECURITY_ACCESS, subfunc=level, service=resp)
        if msg is None:
            return msg
        if msg[0] == 0x7f:
            print("Error getting seed:", msg.encode('hex'))

        else:
            seed = msg[2:]
            if isinstance(secret, str):
                # If key is a string convert it to bytes
                key = bytes(self._key_from_seed(seed, bytes.fromhex(secret.replace(' ', ''))))
            else:
                key = bytes(self._key_from_seed(seed, secret))

            resp = struct.pack('>BB',SVC_SECURITY_ACCESS+0x40, level+1)
            msg = self._do_Function(SVC_SECURITY_ACCESS, subfunc=level + 1, data=key, service=resp)
            return msg

    def _key_from_seed(self, seed, secret):
        """Generates the key for a specific SecurityAccess seed request.
            @seed = the SecurityAccess seed received from the ECU.  Formatted
                    as a hex string with spaces between each seed byte.
            @secret = a SecurityAccess algorithm specific key
           Returns the key, as a string of key bytes.
        """
        print("Not implemented in this class")
        return []


def printUDSSession(c, tx_arbid, rx_arbid=None, paginate=45, ignore_tp=True, uds_service=None):
    '''
    Prints UDS Session information for the given rx/tx arbid.
    ignore_tp - Ignore Tester Present messages
    uds_service - specify a specific uds service
    '''
    uds_services = []
    if rx_arbid is None:
        rx_arbid = tx_arbid + 8  # by UDS spec

    msgs = [msg for msg in c.genCanMsgs(arbids=[tx_arbid, rx_arbid])]

    msgs_idx = 0

    linect = 1
    while msgs_idx < len(msgs):
        arbid, isotpmsg, count = cisotp.msg_decode(msgs, msgs_idx)
        svc = isotpmsg[0]
        mtype = (RESP_CODES, UDS_SVCS)[arbid == tx_arbid].get(svc, '')
        if mtype not in uds_services:
            uds_services.append(mtype)

        if (not (ignore_tp and (isotpmsg[0] == 0x3e or isotpmsg[0] == 0x7e))):
            if (uds_service is None or isotpmsg[0] in uds_service):
                print("Message: (0x%x) (%s:%s) \t %-30s %s" % (arbid, count, msgs_idx, isotpmsg.hex(), mtype))
                linect += 1
        msgs_idx += count

        if paginate:
            if linect % paginate == 0:
                input("%x)  PRESS ENTER" % linect)
    
    print("\nThe following UDS services were seen in this data set")
    for svc in uds_services:
        print(svc)


def saveDataTransfer(c, offset, tx_arbid, rx_arbid, fname):
    ''' offset is the index of the Request Upload or Request Download message
        as reported by the printUDSSession routine
    '''
    msgs = [msg for msg in c.genCanMsgs(arbids=[tx_arbid, rx_arbid])]

    msgs_idx = offset

    arbid, isotpmsg, count = cisotp.msg_decode(msgs, msgs_idx)
    print(isotpmsg.hex())

    if(isotpmsg[0] != 0x34 and isotpmsg[0] != 0x35):
        print("Index %d is not a Request Upload or Request Download message" % msgs_idx)
        return

    # Check for encryption and compression
    if((isotpmsg[1] & 0x0F) > 0):
        print("Encryption in use: %x" % isotpmsg[1] & 0xF)
    else:
        print("No Encryption is in use")

    if((isotpmsg[1] & 0xF0) > 0):
        print("Compression in use: %x" % (isotpmsg[1] & 0xF0) >> 4)
    else:
        print("No Compression in use")

    # Get memory addresses and data sizes
    mem_addr_numbytes = isotpmsg[2] & 0x0F
    mem_size_numbytes = (isotpmsg[2] & 0xF0) >> 4
    mem_addr = 0
    mem_size = 0
    for i in range(0, mem_addr_numbytes):
        mem_addr = mem_addr << 8
        mem_addr = mem_addr + isotpmsg[3 + i]
    for i in range(0, mem_size_numbytes):
        mem_size = mem_size << 8
        mem_size = mem_size + isotpmsg[3 + mem_addr_numbytes + i]

    print("Transferring 0x%x bytes to/from address 0x%08x" % (mem_size, mem_addr))

    # Next message should be a positive response along with block size
    msgs_idx = msgs_idx + count
    arbid, isotpmsg, count = cisotp.msg_decode(msgs, msgs_idx)

    if(isotpmsg[0] != 0x74 and isotpmsg[0] != 0x75):
        print("Did not receive a positive response: ", isotpmsg.hex())
        return

    blk_size_numbytes = (isotpmsg[1] & 0xF0) >> 4
    blk_size = 0
    for i in range(0, blk_size_numbytes):
        blk_size = blk_size << 8
        blk_size = blk_size + isotpmsg[2 + i]

    print("Block size is 0x%x" % blk_size)

    # We should start transferring the data here
    msgs_idx = msgs_idx + count
    expected_blocks = math.ceil(mem_size / (blk_size - 2))
    data = bytearray()

    # Loop through each block
    for block in range(0, expected_blocks):
        arbid, isotpmsg, count = cisotp.msg_decode(msgs, msgs_idx)

        if(isotpmsg[0] != 0x36):
            print("Next message is not the transfer data message: ", isotpmsg.hex())
            return
        if(isotpmsg[1] != (block + 1) % 256):
            print("Unexpected block number %x: Expecting %x" % (isotpmsg[1], (block + 1) % 256))
        
        data = data + isotpmsg[2:]

        # Typically you get a Response Pending "error" frame after the message is received
        pos_resp = False

        msgs_idx = msgs_idx + count
        while(not pos_resp):
            arbid, isotpmsg, count = cisotp.msg_decode(msgs, msgs_idx)

            if(isotpmsg[0] == 0x76):
                if(isotpmsg[1] == (block + 1) % 256):
                    pos_resp = True
                else:
                    print("Incorrect block number in positive response. Actual %x Expected: %x", (isotpmsg[0], (block + 1) % 256))
                    return
            elif(isotpmsg[0] == 0x7f and isotpmsg[2] == 0x78):
                msgs_idx = msgs_idx + count
                continue
            else:
                print("Next message is not a positive response or an expected negative response")
                return

            msgs_idx = msgs_idx + count

    print("Found", hex(len(data)), "Bytes. Expected", hex(mem_size), "Bytes.")
    if(len(data) != mem_size):
        print("ACTUAL DATA DOES NOT MATCH EXPECTED DATA")
        return

    print("Writing data to file", fname)
    with open(fname, "wb") as binary_file:
        binary_file.write(data)







