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

"""

import struct
import logging
from enum import Enum

import gzip
from typing import Optional, cast

import can
import can.typechecking
from can.message import Message
from can.listener import Listener
from .generic import BaseIOHandler


class PcapParseError(Exception):
    """Pcap file could not be parsed correctly."""

LOG = logging.getLogger(__name__)

GLOBAL_HEADER_FORMAT = 'IHHiIII'
GLOBAL_HEADER_STRUCT = struct.Struct(GLOBAL_HEADER_FORMAT)
PACKET_HEADER_FORMAT = 'IIII'
PACKET_HEADER_STRUCT = struct.Struct(PACKET_HEADER_FORMAT)

CAN_MSG_EXT = 0x80000000
CAN_ERR_FLAG = 0x20000000
CAN_ERR_BUSERROR = 0x00000080
CAN_ERR_DLC = 8

class Precision(Enum):
    ms = 1
    ns = 2

class PcapGlobalHeader():
    def __init__(self, data, endian):
        unpacked = struct.unpack(endian + GLOBAL_HEADER_STRUCT, data) # FIXME: We need the endian here
        self.magic_number = unpacked[0] # magic number
        self.version_major = unpacked[1] # major version number
        self.version_minor = unpacked[2] # minor version number
        self.thiszone = unpacked[3] # GMT to local correction
        self.sigfigs = unpacked[4] # accuracy of timestamps
        self.snaplen = unpacked[5] # max length of captured packets, in octets
        self.network = unpacked[6] # data link type

class PcapPacket():
    def __init__(self, header_data, endian):
        unpacked = struct.unpack(endian + PCAP_PACKET_HEADER_FORMAT, header_data)
        self.ts_sec = unpacked[0]
        self.ts_usec = unpacked[1]
        self.incl_len = unpacked[2]
        self.orig_len = unpacked[3]




class PcapLogReader(BaseIOHandler):
    """
    Iterator over CAN messages from a .log Logging File (candump -L).

    .. note::
        .log-format looks for example like this:

        ``(0.0) vcan0 001#8d00100100820100``
    """

    def __init__(self, file):
        """
        :param file: a path-like object or as file-like object to read from
                     If this is a file-like object, is has to opened in text
                     read mode, not binary read mode.
        """
        #super().__init__(file, mode="rb")
        mode="rb"
        if file is None or (hasattr(file, "read") and hasattr(file, "write")):
            # file is None or some file-like object
            self.file = cast(Optional[can.typechecking.FileLike], file)
        else:
            # file is some path-like object
            # FIXME: Use propper .gz detection
            try:
                self.file = gzip.open(cast(can.typechecking.StringPathLike, file), mode)
            except:
                self.file = open(cast(can.typechecking.StringPathLike, file), mode)

        global_header_data = self.file.read(GLOBAL_HEADER_STRUCT.size)

        # Read the first 4 bytes the original format to get the writers magic number
        writer_magic_number = global_header_data[0:4]
        if writer_magic_number == b"\xa1\xb2\xc3\xd4":  # big endian
            # TODO: Looks ugly
            self.endian = ">"
            # TODO: Call this timestamp_precision and use an enum for the possible values
            self.timestamp_precision = Precision.ms
        elif writer_magic_number == b"\xd4\xc3\xb2\xa1":  # little endian
            self.endian = "<"
            self.timestamp_precision = Precision.ms
        elif writer_magic_number == b"\xa1\xb2\x3c\x4d":  # big endian, nanosecond-precision
            self.endian = ">"
            self.timestamp_precision = Precision.ms
        elif writer_magic_number == b"\x4d\x3c\xb2\xa1":  # little endian, nanosecond-precision
            self.endian = "<"
            self.timestamp_precision = Precision.ms
        else:
            raise PcapParseError("Unexpected endian / precision definition")

        global_header = PcapGlobalHeader(global_header_data, self.endian)

        # We only use socketcan log files 
        # DLT_CAN_SOCKETCAN = 227
        # https://www.tcpdump.org/linktypes.html
        if global_header.network != 227:
            raise PcapParseError("Unsupported link type")

        # TODO: Check against snaplen for normal and extended DLC

        super().__init__()

        # TODO: If linktype is not Socketcan (227) throw error
        # https://github.com/JarryShaw/PyPCAPKit/blob/b2e22423981209662e4c42608fa80666eed2bb2e/pcapkit/const/reg/linktype.py#L236

    def __iter__(self):
        for line in self.file:

            # skip empty lines
            temp = line.strip()
            if not temp:
                continue

            timestamp, channel, frame = temp.split()
            timestamp = float(timestamp[1:-1])
            canId, data = frame.split("#")
            if channel.isdigit():
                channel = int(channel)

            isExtended = len(canId) > 3
            canId = int(canId, 16)

            if data and data[0].lower() == "r":
                isRemoteFrame = True

                if len(data) > 1:
                    dlc = int(data[1:])
                else:
                    dlc = 0

                dataBin = None
            else:
                isRemoteFrame = False

                dlc = len(data) // 2
                dataBin = bytearray()
                for i in range(0, len(data), 2):
                    dataBin.append(int(data[i : (i + 2)], 16))

            if canId & CAN_ERR_FLAG and canId & CAN_ERR_BUSERROR:
                msg = Message(timestamp=timestamp, is_error_frame=True)
            else:
                msg = Message(
                    timestamp=timestamp,
                    arbitration_id=canId & 0x1FFFFFFF,
                    is_extended_id=isExtended,
                    is_remote_frame=isRemoteFrame,
                    dlc=dlc,
                    data=dataBin,
                    channel=channel,
                )
            yield msg

        self.stop()


# class CanutilsLogWriter(BaseIOHandler, Listener):
#     """Logs CAN data to an ASCII log file (.log).
#     This class is is compatible with "candump -L".

#     If a message has a timestamp smaller than the previous one (or 0 or None),
#     it gets assigned the timestamp that was written for the last message.
#     It the first message does not have a timestamp, it is set to zero.
#     """

#     def __init__(self, file, channel="vcan0", append=False):
#         """
#         :param file: a path-like object or as file-like object to write to
#                      If this is a file-like object, is has to opened in text
#                      write mode, not binary write mode.
#         :param channel: a default channel to use when the message does not
#                         have a channel set
#         :param bool append: if set to `True` messages are appended to
#                             the file, else the file is truncated
#         """
#         mode = "a" if append else "w"
#         super().__init__(file, mode=mode)

#         self.channel = channel
#         self.last_timestamp = None

#     def on_message_received(self, msg):
#         # this is the case for the very first message:
#         if self.last_timestamp is None:
#             self.last_timestamp = msg.timestamp or 0.0

#         # figure out the correct timestamp
#         if msg.timestamp is None or msg.timestamp < self.last_timestamp:
#             timestamp = self.last_timestamp
#         else:
#             timestamp = msg.timestamp

#         channel = msg.channel if msg.channel is not None else self.channel

#         if msg.is_error_frame:
#             self.file.write(
#                 "(%f) %s %08X#0000000000000000\n"
#                 % (timestamp, channel, CAN_ERR_FLAG | CAN_ERR_BUSERROR)
#             )

#         elif msg.is_remote_frame:
#             if msg.is_extended_id:
#                 self.file.write(
#                     "(%f) %s %08X#R\n" % (timestamp, channel, msg.arbitration_id)
#                 )
#             else:
#                 self.file.write(
#                     "(%f) %s %03X#R\n" % (timestamp, channel, msg.arbitration_id)
#                 )

#         else:
#             data = ["{:02X}".format(byte) for byte in msg.data]
#             if msg.is_extended_id:
#                 self.file.write(
#                     "(%f) %s %08X#%s\n"
#                     % (timestamp, channel, msg.arbitration_id, "".join(data))
#                 )
#             else:
#                 self.file.write(
#                     "(%f) %s %03X#%s\n"
#                     % (timestamp, channel, msg.arbitration_id, "".join(data))
#                 )
