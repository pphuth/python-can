"""
This module works with CAN data in Pcap log files (*.pcap).
The specification from the binary logging file is taken from
https://wiki.wireshark.org/Development/LibpcapFileFormat

The Pcap log file has a global header, containing some global information.
Followed by zero or more records for each captured packet.
Each record consists of a packet header and a packet data segement.
|-------------|-------------|-----------|-------------|-----------|---|
|Global Header|Packet Header|Packet Data|Packet Header|Packet Data|...|
|-------------|-------------|-----------|-------------|-----------|---|
The packet header can be a concatination of multiple 'pseudo' headers
(see 'linux cooked' header for this).
"""

import struct
import logging
from enum import Enum

import gzip
from typing import cast, Optional

import can
#from can.interfaces.socketcan.constants import *
import can.typechecking
from can.message import Message
from can.listener import Listener
from can.util import dlc2len
from .generic import BaseIOHandler


class PcapParseError(Exception):
    """Pcap file could not be parsed correctly."""

LOG = logging.getLogger(__name__)

# Generic PCAP file headers
GLOBAL_HEADER_FORMAT = 'IHHiIII'
GLOBAL_HEADER_STRUCT = struct.Struct(GLOBAL_HEADER_FORMAT)
PACKET_HEADER_FORMAT = 'IIII'
PACKET_HEADER_STRUCT = struct.Struct(PACKET_HEADER_FORMAT)


## Package headers
# LINKTYPE_CAN_SOCKETCAN / DLT_CAN_SOCKETCAN -> 227
# LINKTYPE_LINUX_SLL / DLT_LINUX_SLL -> 113
# LINKTYPE_LINUX_SLL2 / DLT_LINUX_SLL2 -> 276
# https://www.tcpdump.org/linktypes.html

# Linux cooked sockets.
DLT_LINUX_SLL = 113

# Pseudo-header as supplied by Linux SocketCAN
DLT_CAN_SOCKETCAN = 227

# Linux cooked sockets v2.
DLT_LINUX_SLL2 = 276


# SLL struct
# See: https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html
SLL_HEADER_FORMAT = '!HHHQH'
SLL_HEADER_STRUCT = struct.Struct(SLL_HEADER_FORMAT)

# SLL v2 struct
# See: https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL2.html
SLL2_HEADER_FORMAT = '!HHIHBBQ'
SLL2_HEADER_STRUCT = struct.Struct(SLL2_HEADER_FORMAT)


# Socketcan header
SOCKETCAN_CAN_ID_FORMAT = "I"
SOCKETCAN_CAN_ID_STRUCT = struct.Struct(SOCKETCAN_CAN_ID_FORMAT)
SOCKETCAN_META_FORMAT = "BBBB"
SOCKETCAN_META_STRUCT = struct.Struct(SOCKETCAN_META_FORMAT)
SOCKETCAN_HEADER_FORMAT = SOCKETCAN_CAN_ID_FORMAT + SOCKETCAN_META_FORMAT
SOCKETCAN_HEADER_STRUCT = struct.Struct(SOCKETCAN_HEADER_FORMAT)


# TODO: Use as many from the internal socketcan config.py as possible
CAN_EFF_FLAG         = 0x80000000 # EFF/SFF is set in the MSB (extended CAN frame)
CAN_RTR_FLAG         = 0x40000000 # remote transmission request 
CAN_ERR_FLAG         = 0x20000000 # error frame 

CAN_FLAG_MASK = CAN_EFF_FLAG | CAN_RTR_FLAG | CAN_ERR_FLAG

CAN_EFF_MASK         = 0x1FFFFFFF # extended frame format (EFF) has a 29 bit identifier 
CAN_SFF_MASK         = 0x000007FF # standard frame format (SFF) has a 11 bit identifier 

# error class (mask) in can_id 
# NOTE: All are unsigned
CAN_ERR_TX_TIMEOUT   = 0x00000001 # TX timeout (by netdevice driver) 
CAN_ERR_LOSTARB      = 0x00000002 # lost arbitration    / data[0]    
CAN_ERR_CTRL         = 0x00000004 # controller problems / data[1]    
CAN_ERR_PROT         = 0x00000008 # protocol violations / data[2..3] 
CAN_ERR_TRX          = 0x00000010 # transceiver status  / data[4]    
CAN_ERR_ACK          = 0x00000020 # received no ACK on transmission 
CAN_ERR_BUSOFF       = 0x00000040 # bus off 
CAN_ERR_BUSERROR     = 0x00000080 # bus error (may flood!) 
CAN_ERR_RESTARTED    = 0x00000100 # controller restarted 
CAN_ERR_RESERVED     = 0x1FFFFE00 # reserved bits 

# CAN FD specific filters
CANFD_BRS = 0x01 # bit rate switch (second bitrate for payload data)
CANFD_ESI = 0x02 # error state indicator of the transmitting node


# The fake link-layer header of Linux cooked packets.
LINUX_SLL_PROTOCOL_OFFSET = 14 # protocol 
LINUX_SLL_LEN             = 16 # length of the header 

# The protocols we have to check for.
LINUX_SLL_P_CAN           = 0x000C # Controller Area Network 
LINUX_SLL_P_CANFD         = 0x000D # Controller Area Network flexible data rate 


class Precision(Enum):
    ms = 1
    ns = 2

class PcapGlobalHeader():
    def __init__(self, data, endian):
        unpacked = struct.unpack(endian + GLOBAL_HEADER_FORMAT, data)
        self.magic_number = unpacked[0] # magic number
        self.version_major = unpacked[1] # major version number
        self.version_minor = unpacked[2] # minor version number
        self.thiszone = unpacked[3] # GMT to local correction
        self.sigfigs = unpacked[4] # accuracy of timestamps
        self.snaplen = unpacked[5] # max length of captured packets, in octets
        self.network = unpacked[6] # data link type

class PcapPacket():
    def __init__(self, header_data, endian):
        unpacked = struct.unpack(endian + PACKET_HEADER_FORMAT, header_data)
        self.ts_sec = unpacked[0]
        self.ts_usec = unpacked[1]
        self.incl_len = unpacked[2]
        self.orig_len = unpacked[3]


class PcapLogReader(BaseIOHandler):
    """
    Iterator over CAN messages from a .pcap logging file (tcpdump -i vcan0).
    Only CAN messages with their corresponding linktypes are supported. Other link types are
    silently ignored.
    """

    def __init__(self, file):
        """
        Read and parse the generic pcap file

        :param file: a path-like object or as file-like object to read from
                     If this is a file-like object, is has to opened in text
                     read mode, not binary read mode.
        """
        #super().__init__(file, mode="rb")
        mode="rb"
        if file is None or (hasattr(file, "read") and hasattr(file, "write")):
            # file parameter is None or a file(-like object)
            self.file = cast(Optional[can.typechecking.FileLike], file)
        else:
            # file parameter is a path(-like object)
            # FIXME: Use propper .gz detection
            try:
                # FIXME: Two read lines for the global header is ugly
                # NOTE: Only with a read we can see if it is a gzip
                self.file = gzip.open(cast(can.typechecking.StringPathLike, file), mode)
                global_header_data = self.file.read(GLOBAL_HEADER_STRUCT.size)
            except:
                self.file = open(cast(can.typechecking.StringPathLike, file), mode)
                global_header_data = self.file.read(GLOBAL_HEADER_STRUCT.size)
        #global_header_data = self.file.read(GLOBAL_HEADER_STRUCT.size)

        # Read the first 4 bytes without specific encoding to get the writers magic number
        writer_magic_number = global_header_data[0:4]
        if writer_magic_number == b"\xa1\xb2\xc3\xd4":  # big endian
            # TODO: Change endian to a type, looks ugly
            self.endian = ">"
            self.timestamp_precision = Precision.ms
        elif writer_magic_number == b"\xd4\xc3\xb2\xa1":  # little endian
            self.endian = "<"
            self.timestamp_precision = Precision.ms
        elif writer_magic_number == b"\xa1\xb2\x3c\x4d":  # big endian, nanosecond-precision
            self.endian = ">"
            self.timestamp_precision = Precision.ns
        elif writer_magic_number == b"\x4d\x3c\xb2\xa1":  # little endian, nanosecond-precision
            self.endian = "<"
            self.timestamp_precision = Precision.ns
        else:
            raise PcapParseError("Unexpected endian / precision definition")

        self.global_header = PcapGlobalHeader(global_header_data, self.endian)

        # We can only use socketcan packages with generic socketcan  and linux-cooked headers
        if self.global_header.network != DLT_CAN_SOCKETCAN and self.global_header.network != DLT_LINUX_SLL and self.global_header.network != DLT_LINUX_SLL2:
            raise PcapParseError("Unsupported link type")


    def __iter__(self):
        """
        Iterate and parse all the packets int the PCAP file
        """
        while True:

            packet_header_data = self.file.read(PACKET_HEADER_STRUCT.size)
            if not packet_header_data:
                # EOF
                break
            packet_header = PcapPacket(packet_header_data, self.endian)

            # Stays `0` when there is no sll header
            linux_sll_size = 0

            # Test against an SLL header
            if self.global_header.network == DLT_LINUX_SLL:
                sll_header_data = self.file.read(SLL_HEADER_STRUCT.size)
                linux_sll_size = SLL_HEADER_STRUCT.size
                _, _, _, _, protocol_type_field = SLL_HEADER_STRUCT.unpack(
                    sll_header_data
                )
                if protocol_type_field != LINUX_SLL_P_CAN and protocol_type_field != LINUX_SLL_P_CANFD:
                    raise PcapParseError("Unsupported SLL protocol type")
            elif self.global_header.network == DLT_LINUX_SLL2:
                sll2_header_data = self.file.read(SLL2_HEADER_STRUCT.size)
                protocol_type_field, _, _, _, _, _, _, _, _ = SLL2_HEADER_STRUCT.unpack(
                    sll2_header_data
                )
                linux_sll_size = SLL2_HEADER_STRUCT.size
                if protocol_type_field != LINUX_SLL_P_CAN and protocol_type_field != LINUX_SLL_P_CANFD:
                    raise PcapParseError("Unsupported SLLv2 protocol type")

            # NOTE: Read the header of the CAN frame (8 byte)
            packet_data_frame_header = self.file.read(SOCKETCAN_HEADER_STRUCT.size)

            can_id_encoding = '>'
            if self.global_header.network == DLT_LINUX_SLL or self.global_header.network == DLT_LINUX_SLL2:
                # CAN-ID encoding for packets with SLL header is host encoding
                # https://github.com/the-tcpdump-group/libpcap/issues/699#issuecomment-383830002
                can_id_encoding = self.endian

            can_id = struct.unpack(
                can_id_encoding + SOCKETCAN_CAN_ID_FORMAT,
                packet_data_frame_header[0:SOCKETCAN_CAN_ID_STRUCT.size]
            )[0]
            can_dlc, reserved0, reserved1, reserved3 = struct.unpack(
                '>' + SOCKETCAN_META_FORMAT,
                packet_data_frame_header[SOCKETCAN_CAN_ID_STRUCT.size:SOCKETCAN_HEADER_STRUCT.size]
            )

            # NOTE Data segment is full pcap data segment minus CAN header and sll segment
            packet_data_frame_length = packet_header.incl_len - (SOCKETCAN_HEADER_STRUCT.size + linux_sll_size)
            # can_dlc - 8 bit CAN header should be remaining
            if packet_data_frame_length == (can_dlc - SOCKETCAN_HEADER_STRUCT.size):
                raise PcapParseError("Data frame size not equal to CAN frame DLC")

            packet_data_frame = self.file.read(packet_data_frame_length)

            timestamp = packet_header.ts_sec + ( packet_header.ts_usec / 1000000 )

            # NOTE: Standard Pcap file do not store the interface name
            # TODO: Add PCAPng to store multi channel
            channel = 0

            if can_id & CAN_ERR_FLAG and can_id & CAN_ERR_BUSERROR:
                msg = Message(
                    timestamp             = timestamp,
                    is_error_frame        = True,
                    is_extended_id        = bool(can_id & CAN_EFF_FLAG),
                    arbitration_id        = can_id & CAN_EFF_MASK,
                    dlc                   = dlc2len(can_dlc),
                    data                  = packet_data_frame,
                    channel               = channel,
                )
            else:
                msg = Message(
                    timestamp             = timestamp,
                    arbitration_id        = can_id & CAN_EFF_MASK,
                    is_extended_id        = bool(can_id & CAN_EFF_FLAG),
                    is_remote_frame       = bool(can_id & CAN_RTR_FLAG),
                    # TODO: Use `LINUX_SLL_P_CANFD` when we can not get it from the CAN frame
                    is_fd                 = bool(reserved0 & CANFD_BRS),
                    bitrate_switch        = bool(reserved0 & CANFD_BRS),
                    error_state_indicator = bool(can_id & CAN_ERR_FLAG),
                    dlc                   = dlc2len(can_dlc),
                    data                  = packet_data_frame,
                    channel               = channel,
                )

            yield msg
        # END OF CAN message loop
        self.stop()
