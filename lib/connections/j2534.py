import ctypes
import glob
import logging
import os
import struct
from ctypes import (
    POINTER,
    WINFUNCTYPE,
    Structure,
    byref,
    c_long,
    c_ulong,
    c_void_p,
    pointer,
)
from enum import Enum


class PASSTHRU_MSG(Structure):
    _fields_ = [
        ("ProtocolID", c_ulong),
        ("RxStatus", c_ulong),
        ("TxFlags", c_ulong),
        ("Timestamp", c_ulong),
        ("DataSize", c_ulong),
        ("ExtraDataindex", c_ulong),
        ("Data", ctypes.c_ubyte * 4128),
    ]


class SCONFIG(Structure):
    _fields_ = [("Parameter", c_ulong), ("Value", c_ulong)]


class SCONFIG_LIST(Structure):
    _fields_ = [("NumOfParams", c_ulong), ("ConfigPtr", POINTER(SCONFIG))]


class J2534:
    dllPassThruOpen = None
    dllPassThruClose = None
    dllPassThruConnect = None
    dllPassThruDisconnect = None
    dllPassThruReadMsgs = None
    dllPassThruWriteMsgs = None
    dllPassThruStartPeriodicMsg = None
    dllPassThruStopPeriodicMsg = None
    dllPassThruGetLastError = None
    dllPassThruReadVersion = None
    dllPassThruStartMsgFilter = None
    dllPassThruIoctl = None

    def __init__(self, windll, rxid, txid):
        global dllPassThruOpen
        global dllPassThruClose
        global dllPassThruConnect
        global dllPassThruDisconnect
        global dllPassThruReadMsgs
        global dllPassThruWriteMsgs
        global dllPassThruStartPeriodicMsg
        global dllPassThruStopPeriodicMsg
        global dllPassThruGetLastError
        global dllPassThruReadVersion
        global dllPassThruStartMsgFilter
        global dllPassThruIoctl

        # Resolve a DLL path that is compatible with the running Python bitness.
        dll_path = self._find_compatible_j2534_dll(windll)
        self.logger = logging.getLogger()

        self.logger.debug(f"Loading J2534 DLL: {dll_path}")
        self.hDLL = ctypes.cdll.LoadLibrary(dll_path)
        self.rxid = rxid.to_bytes(4, "big")
        self.txid = txid.to_bytes(4, "big")

        self.logger = logging.getLogger()

        dllPassThruOpenProto = WINFUNCTYPE(c_long, c_void_p, POINTER(c_ulong))

        dllPassThruOpenParams = (1, "pName", 0), (1, "pDeviceID", 0)
        dllPassThruOpen = dllPassThruOpenProto(
            ("PassThruOpen", self.hDLL), dllPassThruOpenParams
        )

        dllPassThruCloseProto = WINFUNCTYPE(c_long, c_ulong)

        dllPassThruCloseParams = ((1, "DeviceID", 0),)
        dllPassThruClose = dllPassThruCloseProto(
            ("PassThruClose", self.hDLL), dllPassThruCloseParams
        )

        dllPassThruConnectProto = WINFUNCTYPE(
            c_long, c_ulong, c_ulong, c_ulong, c_ulong, POINTER(c_ulong)
        )

        dllPassThruConnectParams = (
            (1, "DeviceID", 0),
            (1, "ProtocolID", 0),
            (1, "Flags", 0),
            (1, "BaudRate", 500000),
            (1, "pChannelID", 0),
        )
        dllPassThruConnect = dllPassThruConnectProto(
            ("PassThruConnect", self.hDLL), dllPassThruConnectParams
        )

        dllPassThruDisconnectProto = WINFUNCTYPE(c_long, c_ulong)

        dllPassThruDisconnectParams = ((1, "ChannelID", 0),)
        dllPassThruDisconnect = dllPassThruDisconnectProto(
            ("PassThruDisconnect", self.hDLL), dllPassThruDisconnectParams
        )

        dllPassThruReadMsgsProto = WINFUNCTYPE(
            c_long, c_ulong, POINTER(PASSTHRU_MSG), POINTER(c_ulong), c_ulong
        )

        dllPassThruReadMsgsParams = (
            (1, "ChannelID", 0),
            (1, "pMsg", 0),
            (1, "pNumMsgs", 0),
            (1, "Timeout", 0),
        )
        dllPassThruReadMsgs = dllPassThruReadMsgsProto(
            ("PassThruReadMsgs", self.hDLL), dllPassThruReadMsgsParams
        )

        dllPassThruWriteMsgsProto = WINFUNCTYPE(
            c_long, c_ulong, POINTER(PASSTHRU_MSG), POINTER(c_ulong), c_ulong
        )

        dllPassThruWriteMsgsParams = (
            (1, "ChannelID", 0),
            (1, "pMsg", 0),
            (1, "pNumMsgs", 0),
            (1, "Timeout", 0),
        )
        dllPassThruWriteMsgs = dllPassThruWriteMsgsProto(
            ("PassThruWriteMsgs", self.hDLL), dllPassThruWriteMsgsParams
        )

        dllPassThruStartPeriodicMsgProto = WINFUNCTYPE(
            c_long, c_ulong, POINTER(PASSTHRU_MSG), POINTER(c_ulong), c_ulong
        )

        dllPassThruStartPeriodicMsgParams = (
            (1, "ChannelID", 0),
            (1, "pMsg", 0),
            (1, "pMsgID", 0),
            (1, "TimeInterval", 0),
        )
        dllPassThruStartPeriodicMsg = dllPassThruStartPeriodicMsgProto(
            ("PassThruStartPeriodicMsg", self.hDLL), dllPassThruStartPeriodicMsgParams
        )

        dllPassThruStopPeriodicMsgProto = WINFUNCTYPE(c_long, c_ulong, c_ulong)

        dllPassThruStopPeriodicMsgParams = (1, "ChannelID", 0), (1, "MsgID", 0)
        dllPassThruStopPeriodicMsg = dllPassThruStopPeriodicMsgProto(
            ("PassThruStopPeriodicMsg", self.hDLL), dllPassThruStopPeriodicMsgParams
        )

        dllPassThruReadVersionProto = WINFUNCTYPE(
            c_long,
            c_ulong,
            POINTER(ctypes.c_char),
            POINTER(ctypes.c_char),
            POINTER(ctypes.c_char),
        )

        dllPassThruReadVersionParams = (
            (1, "DeviceID", 0),
            (1, "pFirmwareVersion", 0),
            (1, "pDllVersion", 0),
            (1, "pApiVersoin", 0),
        )

        dllPassThruReadVersion = dllPassThruReadVersionProto(
            ("PassThruReadVersion", self.hDLL), dllPassThruReadVersionParams
        )

        dllPassThruGetLastErrorProto = WINFUNCTYPE(c_long, POINTER(ctypes.c_char))
        dllPassThruGetLastErrorParams = ((1, "pErrorMsg", 0),)
        dllPassThruGetLastError = dllPassThruGetLastErrorProto(
            ("PassThruGetLastError", self.hDLL), dllPassThruGetLastErrorParams
        )

        dllPassThruStartMsgFilterProto = WINFUNCTYPE(
            c_long,
            c_ulong,
            c_ulong,
            POINTER(PASSTHRU_MSG),
            POINTER(PASSTHRU_MSG),
            POINTER(PASSTHRU_MSG),
            POINTER(c_ulong),
        )

        dllPassThruStartMsgFilterParams = (
            (1, "ChannelID", 0),
            (1, "FilterType", 0),
            (1, "pMaskMsg", 0),
            (1, "pPatternMsg", 0),
            (1, "pFlowControlMsg", 0),
            (1, "pMsgID", 0),
        )

        dllPassThruStartMsgFilter = dllPassThruStartMsgFilterProto(
            ("PassThruStartMsgFilter", self.hDLL), dllPassThruStartMsgFilterParams
        )

        dllPassThruIoctlProto = WINFUNCTYPE(
            c_long, c_ulong, c_ulong, c_void_p, c_void_p
        )

        dllPassThruIoctlParams = (
            (1, "Handle", 0),
            (1, "IoctlID", 0),
            (1, "pInput", 0),
            (1, "pOutput", 0),
        )

        dllPassThruIoctl = dllPassThruIoctlProto(
            ("PassThruIoctl", self.hDLL), dllPassThruIoctlParams
        )

    def _is_pe_64bit(self, filepath: str) -> bool:
        """Return True if the PE file at filepath is 64-bit (IMAGE_FILE_MACHINE_AMD64)."""
        try:
            with open(filepath, "rb") as f:
                data = f.read(0x200)
                if len(data) < 0x40:
                    return False
                e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
                # Ensure we have enough bytes to read machine
                f.seek(e_lfanew + 4)
                machine_bytes = f.read(2)
                if len(machine_bytes) < 2:
                    return False
                machine = struct.unpack_from("<H", machine_bytes)[0]
                # IMAGE_FILE_MACHINE_AMD64 == 0x8664
                return machine == 0x8664
        except Exception:
            return False

    def _find_compatible_j2534_dll(self, preferred_path: str) -> str:
        """Find a J2534 DLL that matches the Python process bitness.

        Order of resolution:
        1. Environment variable J2534_DLL_PATH
        2. preferred_path passed into this function
        3. search common Program Files locations for op20pt*.dll

        Raises RuntimeError with guidance if no compatible DLL is found.
        """
        desired_64 = struct.calcsize("P") * 8 == 64

        # candidate sources
        candidates = []
        env_path = os.environ.get("J2534_DLL_PATH")
        if env_path:
            candidates.append(env_path)

        if preferred_path:
            candidates.append(preferred_path)

        # Common vendor locations to search for OpenPort drivers
        common_roots = [
            r"C:\Program Files\OpenECU",
            r"C:\Program Files (x86)\OpenECU",
            r"C:\Program Files",
            r"C:\Program Files (x86)",
        ]

        for root in common_roots:
            try:
                pattern = os.path.join(root, "**", "op20pt*.dll")
                candidates.extend(glob.glob(pattern, recursive=True))
            except Exception:
                continue

        # Filter unique candidates and check bitness
        seen = set()
        for cand in candidates:
            if not cand or cand in seen:
                continue
            seen.add(cand)
            if not os.path.exists(cand):
                continue
            is64 = self._is_pe_64bit(cand)
            if is64 == desired_64:
                return cand

        # Nothing matched exactly; if preferred exists and matches desired bitness, return it
        if preferred_path and os.path.exists(preferred_path):
            try:
                if self._is_pe_64bit(preferred_path) == desired_64:
                    return preferred_path
            except Exception:
                pass

        # Construct helpful error
        bit_txt = "64-bit" if desired_64 else "32-bit"
        raise RuntimeError(
            f"No compatible J2534 DLL found for {bit_txt} Python.\n"
            f"Set the environment variable J2534_DLL_PATH to the full path of a compatible J2534 DLL,\n"
            f"or install the vendor's {bit_txt} J2534 driver. Searched candidates: {list(seen)}"
        )

    def PassThruOpen(self, pDeviceID=None):
        if not pDeviceID:
            pDeviceID = ctypes.c_ulong()

        result = dllPassThruOpen(byref(ctypes.c_int()), byref(pDeviceID))
        return Error_ID(result), pDeviceID

    def PassThruConnect(self, deviceID, protocol, baudrate, pChannelID=None):
        if not pChannelID:
            pChannelID = c_ulong()

        result = dllPassThruConnect(deviceID, protocol, 0, baudrate, byref(pChannelID))
        return Error_ID(result), pChannelID

    def PassThruClose(self, DeviceID):
        result = dllPassThruClose(DeviceID)
        return Error_ID(result)

    def PassThruDisconnect(self, ChannelID):
        result = dllPassThruDisconnect(ChannelID)
        return Error_ID(result)

    def PassThruReadMsgs(self, ChannelID, protocol, pNumMsgs=1, Timeout=100):
        pMsg = PASSTHRU_MSG()
        pMsg.ProtocolID = protocol

        pNumMsgs = c_ulong(pNumMsgs)
        # self.logger.debug("Calling readMsgs with timeout: " + str(Timeout))
        while 1:
            # breakpoint()
            result = dllPassThruReadMsgs(
                ChannelID, byref(pMsg), byref(pNumMsgs), c_ulong(Timeout)
            )
            if Error_ID(result) == Error_ID.ERR_BUFFER_EMPTY or pNumMsgs == 0:
                return None, None, 0
            elif pMsg.RxStatus == 0:
                return Error_ID(result), bytes(pMsg.Data[4 : pMsg.DataSize]), pNumMsgs
            # else:
            #    self.logger.debug("No valid response received: " + str(pMsg.RxStatus) + " - " + str(bytes(pMsg.Data[0:pMsg.DataSize])) + " - " + str(pMsg.Error_ID(result)))

    def PassThruWriteMsgs(self, ChannelID, Data, protocol, pNumMsgs=1, Timeout=1000):
        txmsg = PASSTHRU_MSG()
        txmsg.TxFlags = TxStatusFlag.ISO15765_FRAME_PAD.value
        txmsg.ProtocolID = protocol

        # VW Testing:
        # Data = b'\x00\x00\x07\xE0' + Data

        # Generic OBD2 testing:
        # Data = b'\x00\x00\x07\x00' + Data

        Data = self.txid + Data
        # self.logger.info("Sending data: " + str(Data.hex()))

        for i in range(0, len(Data)):
            txmsg.Data[i] = Data[i]

        txmsg.DataSize = len(Data)

        result = dllPassThruWriteMsgs(
            ChannelID, byref(txmsg), byref(c_ulong(pNumMsgs)), c_ulong(Timeout)
        )
        # self.logger.debug("Sent data, received response" + str(Error_ID(result)))
        return Error_ID(result)

    def PassThruStartPeriodicMsg(self, ChannelID, Data, MsgID=0, TimeInterval=100):
        pMsg = PASSTHRU_MSG()

        pMsg.Data = Data
        pMsg.DataSize = len(Data)

        result = dllPassThruStartPeriodicMsg(
            ChannelID, byref(pMsg), byref(c_ulong(MsgID)), c_ulong(TimeInterval)
        )

        return Error_ID(result)

    def PassThruStopPeriodicMsg(self, ChannelID, MsgID):
        result = dllPassThruStopPeriodicMsg(ChannelID, MsgID)

        return Error_ID(result)

    def PassThruGetLastError(self):
        pErrorMsg = (ctypes.c_char * 80)()

        dllPassThruGetLastError(pErrorMsg)

        return pErrorMsg

    def PassThruReadVersion(self, DeviceID):
        pFirmwareVersion = (ctypes.c_char * 80)()
        pDllVersion = (ctypes.c_char * 80)()
        pApiVersion = (ctypes.c_char * 80)()
        result = dllPassThruReadVersion(
            DeviceID, pFirmwareVersion, pDllVersion, pApiVersion
        )

        return Error_ID(result), pFirmwareVersion, pDllVersion, pApiVersion

    def PassThruIoctl(self, Handle, IoctlID, ioctlInput=None, ioctlOutput=None):
        if ioctlInput is None:
            pInput = POINTER(c_ulong)()
        else:
            inputParam = SCONFIG()
            inputParam.Parameter = ioctlInput.Parameter
            inputParam.Value = ioctlInput.Value

            pInput = SCONFIG_LIST()
            pInput.NumOfParams = c_ulong(1)
            pInput.ConfigPtr = pointer(inputParam)

        if ioctlOutput is None:
            pOutput = None
        else:
            pOutput = byref(ioctlOutput)

        result = dllPassThruIoctl(
            Handle, c_ulong(IoctlID.value), byref(pInput), pOutput
        )

        if ioctlInput:
            self.logger.debug(
                "    pinput: " + str(Ioctl_Parameters(inputParam.Parameter))
            )
            self.logger.debug("    pinput: " + str(inputParam.Value))
            self.logger.debug("    result: " + str(Error_ID(result)))

        return Error_ID(result)

    def PassThruStartMsgFilter(self, ChannelID, protocol):
        # VW Testing
        # txID = bytes([0x00, 0x00, 0x07, 0xE0])

        # Generic OBD2 testing
        # txID = bytes([0x00, 0x00, 0x07, 0x00])

        # rxID = bytes([0x00, 0x00, 0x07, 0xE8])

        txmsg = PASSTHRU_MSG()
        msgMask = PASSTHRU_MSG()
        msgPattern = PASSTHRU_MSG()
        msgFlow = PASSTHRU_MSG()

        txmsg.ProtocolID = protocol
        txmsg.RxStatus = 0
        txmsg.TxFlags = TxStatusFlag.ISO15765_FRAME_PAD.value
        txmsg.Timestamp = 0
        txmsg.DataSize = 4

        msgMask.ProtocolID = protocol
        msgMask.RxStatus = 0
        msgMask.TxFlags = TxStatusFlag.ISO15765_FRAME_PAD.value
        msgMask.Timestamp = 0
        msgMask.DataSize = 4
        for i in range(0, 4):
            msgMask.Data[i] = 0xFF

        msgPattern.ProtocolID = protocol
        msgPattern.RxStatus = 0
        msgPattern.TxFlags = TxStatusFlag.ISO15765_FRAME_PAD.value
        msgPattern.Timestamp = 0
        msgPattern.DataSize = 4

        msgFlow.ProtocolID = protocol
        msgFlow.RxStatus = 0
        msgFlow.TxFlags = TxStatusFlag.ISO15765_FRAME_PAD.value
        msgFlow.Timestamp = 0
        msgFlow.DataSize = 4

        for i in range(0, len(self.txid)):
            msgFlow.Data[i] = self.txid[i]

        for i in range(0, len(self.rxid)):
            msgPattern.Data[i] = self.rxid[i]

        msgID = c_ulong(0)

        result = dllPassThruStartMsgFilter(
            ChannelID,
            c_ulong(Filter.FLOW_CONTROL_FILTER.value),
            byref(msgMask),
            byref(msgPattern),
            byref(msgFlow),
            byref(msgID),
        )

        # for i in range(0, len(self.rxid)):
        #    msgFlow.Data[i] = self.rxid[i]

        # for i in range(0, len(self.txid)):
        #    msgPattern.Data[i] = self.txid[i]

        # result = dllPassThruStartMsgFilter(ChannelID, c_ulong(Filter.FLOW_CONTROL_FILTER.value), byref(msgMask), byref(msgPattern), byref(msgFlow), byref(msgID))

        return Error_ID(result)


class Error_ID(Enum):
    ERR_SUCCESS = 0x00
    STATUS_NOERROR = 0x00
    ERR_NOT_SUPPORTED = 0x01
    ERR_INVALID_CHANNEL_ID = 0x02
    ERR_INVALID_PROTOCOL_ID = 0x03
    ERR_NULL_PARAMETER = 0x04
    ERR_INVALID_IOCTL_VALUE = 0x05
    ERR_INVALID_FLAGS = 0x06
    ERR_FAILED = 0x07
    ERR_DEVICE_NOT_CONNECTED = 0x08
    ERR_TIMEOUT = 0x09
    ERR_INVALID_MSG = 0x0A
    ERR_INVALID_TIME_INTERVAL = 0x0B
    ERR_EXCEEDED_LIMIT = 0x0C
    ERR_INVALID_MSG_ID = 0x0D
    ERR_DEVICE_IN_USE = 0x0E
    ERR_INVALID_IOCTL_ID = 0x0F
    ERR_BUFFER_EMPTY = 0x10
    ERR_BUFFER_FULL = 0x11
    ERR_BUFFER_OVERFLOW = 0x12
    ERR_PIN_INVALID = 0x13
    ERR_CHANNEL_IN_USE = 0x14
    ERR_MSG_PROTOCOL_ID = 0x15
    ERR_INVALID_FILTER_ID = 0x16
    ERR_NO_FLOW_CONTROL = 0x17
    ERR_NOT_UNIQUE = 0x18
    ERR_INVALID_BAUDRATE = 0x19
    ERR_INVALID_DEVICE_ID = 0x1A


class Protocol_ID(Enum):
    J1850VPW = 1
    J1850PWM = 2
    ISO9141 = 3
    ISO14230 = 4
    CAN = 5
    ISO15765 = 6
    SCI_A_ENGINE = 7  # OP2.0: Not supported
    SCI_A_TRANS = 8  # OP2.0: Not supported
    SCI_B_ENGINE = 9  # OP2.0: Not supported
    SCI_B_TRANS = 10  # OP2.0: Not supported


class Filter(Enum):
    PASS_FILTER = 0x00000001
    BLOCK_FILTER = 0x00000002
    FLOW_CONTROL_FILTER = 0x00000003


class TxStatusFlag(Enum):
    ISO15765_FRAME_PAD = 0x00000040
    WAIT_P3_MIN_ONLY = 0x00000200
    SW_CAN_HV_TX = 0x00000400  # OP2.0: Not supported
    SCI_MODE = 0x00400000  # OP2.0: Not supported
    SCI_TX_VOLTAGE = 0x00800000  # OP2.0: Not supported


class Ioctl_ID(Enum):
    GET_CONFIG = 0x01
    SET_CONFIG = 0x02
    CLEAR_RX_BUFFER = 0x08


class Ioctl_Parameters(Enum):
    ISO15765_BS = 0x1E
    ISO15765_STMIN = 0x1F
    DATA_BITS = 0x20
    FIVE_BAUD_MOD = 0x21
    BS_TX = 0x22
    STMIN_TX = 0x23


class Ioctl_Flags(Enum):
    TX_IOCTL_BASE = 0x70000
    TX_IOCTL_SET_DLL_DEBUG_FLAGS = 0x70001
    TX_IOCTL_DLL_DEBUG_FLAG_J2534_CALLS = 0x00000001
