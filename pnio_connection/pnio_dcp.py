# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2019 Stefan Mehner (stefan.mehner@b-tu.de)

# scapy.contrib.description = Profinet DCP layer
# scapy.contrib.status = loads

from enum import IntEnum
from scapy.compat import orb
from scapy.all import Packet, bind_layers, Padding
from scapy.fields import (
    ByteEnumField,
    ConditionalField,
    FieldLenField,
    FieldListField,
    FlagsField,
    IPField,
    LenField,
    MACField,
    MultiEnumField,
    MultipleTypeField,
    PacketListField,
    PadField,
    ReversePadField,
    ShortEnumField,
    ShortField,
    StrField,
    StrLenField,
    XByteField,
    XIntField,
    XShortField,
)

# minimum packet is 60 bytes.. 14 bytes are Ether()
MIN_PACKET_LENGTH = 44

#####################################################
#                     Constants                     #
#####################################################

DCP_HELLO_FRAME_ID = 0xFEFC
DCP_GET_SET_FRAME_ID = 0xFEFD
DCP_IDENTIFY_REQUEST_FRAME_ID = 0xFEFE
DCP_IDENTIFY_RESPONSE_FRAME_ID = 0xFEFF

class DCP_SERVICE_ID(IntEnum):
    RESERVED = 0x00
    MANUFACTURER_SPECIFIC_01 = 0x01 # N.B. Spec says "reserved"
    MANUFACTURER_SPECIFIC_02 = 0x02 # N.B. Spec says "reserved"
    GET = 0x03
    SET = 0x04
    IDENTIFY = 0x05
    HELLO = 0x06

class DCP_SERVICE_TYPE(IntEnum):
    REQUEST = 0x00
    RESPONSE_SUCCESS = 0x01
    RESPONSE_REQUEST_NOT_SUPPORTED = 0x01 | 0x04

class DCP_DEVICE_ROLE(IntEnum):
    DEVICE = 0x01
    CONTROLLER = 0x02
    MULTIDEVICE = 0x04
    SUPERVISOR = 0x08

DCP_OPTIONS = {
    0x00: "reserved",
    0x01: "IP",
    0x02: "Device properties",
    0x03: "DHCP",
    0x04: "Reserved",
    0x05: "Control",
    0x06: "Device Initiative",
    0xff: "All Selector"
}
DCP_OPTIONS.update({i: "reserved" for i in range(0x07, 0x7f)})
DCP_OPTIONS.update({i: "Manufacturer specific" for i in range(0x80, 0xfe)})

DCP_SUBOPTIONS = {
    # ip
    0x01: {
        0x00: "Reserved",
        0x01: "MAC Address",
        0x02: "IP Parameter",
        0x03: "Full IP Suite",
    },
    # device properties
    0x02: {
        0x00: "Reserved",
        0x01: "Manufacturer specific (Type of Station)",
        0x02: "Name of Station",
        0x03: "Device ID",
        0x04: "Device Role",
        0x05: "Device Options",
        0x06: "Alias Name",
        0x07: "Device Instance",
        0x08: "OEM Device ID",
    },
    # dhcp
    0x03: {
        0x0c: "Host name",
        0x2b: "Vendor specific",
        0x36: "Server identifier",
        0x37: "Parameter request list",
        0x3c: "Class identifier",
        0x3d: "DHCP client identifier",
        0x51: "FQDN, Fully Qualified Domain Name",
        0x61: "UUID/GUID-based Client",
        0xff: "Control DHCP for address resolution"
    },
    # control
    0x05: {
        0x00: "Reserved",
        0x01: "Start Transaction",
        0x02: "End Transaction",
        0x03: "Signal",
        0x04: "Response",
        0x05: "Reset Factory Settings",
        0x06: "Reset to Factory"
    },
    # device initiative
    0x06: {
        0x00: "Reserved",
        0x01: "Device Initiative"
    },
    0xff: {
        0xff: "ALL Selector"
    }
}

BLOCK_INFOS = {
    0x00: "Reserved",
}
BLOCK_INFOS.update({i: "reserved" for i in range(0x01, 0xff)})


IP_BLOCK_INFOS = {
    0x0000: "IP not set",
    0x0001: "IP set",
    0x0002: "IP set by DHCP",
    0x0080: "IP not set (address conflict detected)",
    0x0081: "IP set (address conflict detected)",
    0x0082: "IP set by DHCP (address conflict detected)",
}
IP_BLOCK_INFOS.update({i: "reserved" for i in range(0x0003, 0x007f)})

BLOCK_ERRORS = {
    0x00: "Ok",
    0x01: "Option unsupp.",
    0x02: "Suboption unsupp. or no DataSet avail.",
    0x03: "Suboption not set",
    0x04: "Resource Error",
    0x05: "SET not possible by local reasons",
    0x06: "In operation, SET not possible",
}

BLOCK_QUALIFIERS = {
    0x0000: "Use the value temporary",
    0x0001: "Save the value permanent",
}
BLOCK_QUALIFIERS.update({i: "reserved" for i in range(0x0002, 0x00ff)})


#####################################################
#                     DCP Blocks                    #
#####################################################

# GENERIC DCP BLOCK

# DCP RESPONSE BLOCKS

class _DataBlock(Packet):
    extra_block_length = 0
    def extract_padding(self, s):
        payload_length = self.dcp_block_length-self.extra_block_length
        # Blocks round up to the nearest 16-bit boundary.
        return s[:payload_length], s[payload_length+(self.dcp_block_length%2):]

    def post_build(self, pkt, pay):
        p = super().post_build(pkt, pay)
        return p + (len(p) % 2) * b'\x00'

class DCPRequestBlock(_DataBlock):
    fields_desc = [
        ByteEnumField("option", 1, DCP_OPTIONS),
        MultiEnumField("sub_option", 2, DCP_SUBOPTIONS, fmt='B',
                       depends_on=lambda p: p.option),
        LenField("dcp_block_length", None),
    ]

class DCPResponseBlock(_DataBlock):
    @property
    def extra_block_length(self):
        if self.block_info is None:
            return 0
        return 2
    fields_desc = [
        ByteEnumField("option", 1, DCP_OPTIONS),
        MultiEnumField("sub_option", 2, DCP_SUBOPTIONS, fmt='B',
                       depends_on=lambda p: p.option),
        LenField("dcp_block_length", None, adjust=lambda l: l+self.extra_block_length),
        ConditionalField(
            ShortEnumField("block_info", 0, BLOCK_INFOS),
            lambda pkt: (pkt.option, pkt.sub_option) != (5, 4),
        ),
    ]

class DCPSetRequestBlock(_DataBlock):
    @property
    def extra_block_length(self):
        if self.block_qualifier is None:
            return 0
        return 2
    fields_desc = [
        ByteEnumField("option", 1, DCP_OPTIONS),
        MultiEnumField("sub_option", 2, DCP_SUBOPTIONS, fmt='B',
                       depends_on=lambda p: p.option),
        LenField("dcp_block_length", None, adjust=lambda l: l+self.extra_block_length),
        ShortEnumField("block_qualifier", 1, BLOCK_QUALIFIERS),
    ]

def _block(**kwargs):
    def f(c):
        bind_layers(DCPRequestBlock, c, **kwargs)
        bind_layers(DCPResponseBlock, c, **kwargs)
        bind_layers(DCPSetRequestBlock, c, **kwargs)
        return c
    return f

# OPTION: IP
@_block(option=1, sub_option=2)
class IPParameterBlock(Packet):
    fields_desc = [
        IPField("ip", "192.168.0.2"),
        IPField("netmask", "255.255.255.0"),
        IPField("gateway", "192.168.0.1"),
    ]

    def extract_padding(self, s):
        return '', s

# TODO: Not documented in the standard?
@_block(option=1, sub_option=3)
class FullIPParameterBlock(Packet):
    fields_desc = [
        IPField("ip", "192.168.0.2"),
        IPField("netmask", "255.255.255.0"),
        IPField("gateway", "192.168.0.1"),
        FieldListField("dnsaddr", [], IPField("", "0.0.0.0"),
                       count_from=lambda x: 4),
    ]

    def extract_padding(self, s):
        return '', s

@_block(option=1, sub_option=1)
class MACAddressBlock(Packet):
    fields_desc = [
        MACField("mac", "00:00:00:00:00:00"),
    ]

    def extract_padding(self, s):
        return '', s


# OPTION: Device Properties
@_block(option=2, sub_option=1)
class ManufacturerSpecificParameterBlock(Packet):
    fields_desc = [
        StrField("device_vendor_value", "et200sp"),
    ]

    def extract_padding(self, s):
        return '', s

@_block(option=2, sub_option=2)
class NameOfStationBlock(Packet):
    fields_desc = [
        StrField("name_of_station", "et200sp"),
    ]

    def extract_padding(self, s):
        return '', s


@_block(option=2, sub_option=3)
class DeviceIDBlock(Packet):
    fields_desc = [
        XShortField("vendor_id", 0x002a),
        XShortField("device_id", 0x0313),
    ]

    def extract_padding(self, s):
        return '', s

@_block(option=2, sub_option=4)
class DeviceRoleBlock(Packet):
    fields_desc = [
        FlagsField("device_role_details", 1, 8, names=dict((i.value, i.name) for i in DCP_DEVICE_ROLE)),
        XByteField("reserved", 0x00),
    ]

    def extract_padding(self, s):
        return '', s


# one DeviceOptionsBlock can contain 1..n different options
class DeviceOption(Packet):
    fields_desc = [
        ByteEnumField("option", 2, DCP_OPTIONS),
        MultiEnumField("sub_option", 5, DCP_SUBOPTIONS, fmt='B',
                       depends_on=lambda p: p.option),
    ]

    def extract_padding(self, s):
        return '', s


@_block(option=2, sub_option=5)
class DeviceOptionsBlock(Packet):
    fields_desc = [
        PacketListField("device_options", [], DeviceOption),
    ]

    def extract_padding(self, s):
        return '', s

@_block(option=2, sub_option=6)
class AliasNameBlock(Packet):
    fields_desc = [
        StrField("alias_name", "et200sp"),
    ]

    def extract_padding(self, s):
        return '', s

@_block(option=2, sub_option=7)
class DeviceInstanceBlock(Packet):
    fields_desc = [
        XByteField("device_instance_high", 0x00),
        XByteField("device_instance_low", 0x01),
    ]

    def extract_padding(self, s):
        return '', s

@_block(option=2, sub_option=8)
class OEMIDBlock(Packet):
    fields_desc = [
        XShortField("vendor_id", 0x002a),
        XShortField("device_id", 0x0313),
    ]

    def extract_padding(self, s):
        return '', s

@_block(option=5, sub_option=4)
class ControlResponseBlock(Packet):
    fields_desc = [
        ByteEnumField("option", 2, DCP_OPTIONS),
        MultiEnumField("sub_option", 2, DCP_SUBOPTIONS, fmt='B',
                       depends_on=lambda p: p.option),
        ByteEnumField("block_error", 0, BLOCK_ERRORS),
    ]
    def extract_padding(self, s):
        return '', s


class DCPDeviceInitiativeBlock(Packet):
    """
        device initiative DCP block
    """
    fields_desc = [
        ByteEnumField("option", 6, DCP_OPTIONS),
        MultiEnumField("sub_option", 1, DCP_SUBOPTIONS, fmt='B',
                       depends_on=lambda p: p.option),
        FieldLenField("dcp_block_length", None, length_of="device_initiative"),
        ShortEnumField("block_info", 0, BLOCK_INFOS),
        ShortField("device_initiative", 1),
    ]

    def extract_padding(self, s):
        return '', s


# GENERIC DCP PACKET

class ProfinetDCP(Packet):
    """
    Profinet DCP Packet

    Requests are handled via ConditionalField because here only 1 Block is used
    every time.

    Response can contain 1..n Blocks, for that you have to use one ProfinetDCP
    Layer with one or multiple DCP*Block Layers::

        ProfinetDCP / DCPNameOfStationBlock / DCPDeviceIDBlock ...

    Example for a DCP Identify All Request::

        Ether(dst="01:0e:cf:00:00:00") /
        ProfinetIO(frameID=DCP_IDENTIFY_REQUEST_FRAME_ID) /
        ProfinetDCP(service_id=DCP_SERVICE_ID_IDENTIFY,
            service_type=DCP_REQUEST, option=255, sub_option=255,
            dcp_data_length=4)

    Example for a DCP Identify Response::

        Ether(dst=dst_mac) /
        ProfinetIO(frameID=DCP_IDENTIFY_RESPONSE_FRAME_ID) /
        ProfinetDCP(
            service_id=DCP_SERVICE_ID_IDENTIFY,
            service_type=DCP_RESPONSE) /
        DCPNameOfStationBlock(name_of_station="device1")

    Example for a DCP Set Request::

        Ether(dst=mac) /
        ProfinetIO(frameID=DCP_GET_SET_FRAME_ID) /
        ProfinetDCP(service_id=DCP_SERVICE_ID_SET, service_type=DCP_REQUEST,
            option=2, sub_option=2, dcp_data_length=14, dcp_block_length=10,
            name_of_station=name, reserved=0)

    """

    name = "Profinet DCP"
    # a DCP PDU consists of some fields and 1..n DCP Blocks
    fields_desc = [
        ByteEnumField("service_id", 5, DCP_SERVICE_ID),
        ByteEnumField("service_type", 0, DCP_SERVICE_TYPE),
        XIntField("xid", 0x01000001),

        ConditionalField(
            ShortField("response_delay_factor", 1), # 0x0001 = no spread, 2-0x1900 = 10ms increments
            lambda pkt: pkt.service_type == 0 and pkt.service_id == 5,
        ),

        ReversePadField(
            LenField("dcp_data_length", None),
            4, # align data length to 4 bytes whether or not response_delay_factor is present.
        )
    ]

    def extract_padding(self, s):
        return s[:self.dcp_data_length], s[self.dcp_data_length:]

    @property
    def frame_id(self):
        match (self.service_type, self.service_id):
            case _, DCP_SERVICE_ID.HELLO:
                return DCP_HELLO_FRAME_ID
            case _, (DCP_SERVICE_ID.GET | DCP_SERVICE_ID.SET):
                return DCP_GET_SET_FRAME_ID
            case DCP_SERVICE_TYPE.REQUEST, DCP_SERVICE_ID.IDENTIFY:
                return DCP_IDENTIFY_REQUEST_FRAME_ID
            case (DCP_SERVICE_TYPE.RESPONSE_SUCCESS | DCP_SERVICE_TYPE.RESPONSE_REQUEST_NOT_SUPPORTED), DCP_SERVICE_ID.IDENTIFY:
                return DCP_IDENTIFY_RESPONSE_FRAME_ID

class ProfinetDCPIdentifyReq(Packet):
    name = "Profinet DCP-Identify-ReqPDU"
    fields_desc = [
        PacketListField("dcp_blocks", [], DCPRequestBlock),
    ]
bind_layers(ProfinetDCP, ProfinetDCPIdentifyReq, service_type=DCP_SERVICE_TYPE.REQUEST, service_id=DCP_SERVICE_ID.IDENTIFY)
class ProfinetDCPIdentifyRes(Packet):
    name = "Profinet DCP-Identify-ResPDU"
    fields_desc = [
        PacketListField("dcp_blocks", [], DCPResponseBlock),
    ]
bind_layers(ProfinetDCP, ProfinetDCPIdentifyRes, service_type=DCP_SERVICE_TYPE.RESPONSE_SUCCESS, service_id=DCP_SERVICE_ID.IDENTIFY)

class ProfinetDCPGetReq(Packet):
    name = "Profinet DCP-Get-ReqPDU"
    fields_desc = [
        PacketListField("device_options", [], DeviceOption),
    ]
bind_layers(ProfinetDCP, ProfinetDCPGetReq, service_type=DCP_SERVICE_TYPE.REQUEST, service_id=DCP_SERVICE_ID.GET)

class ProfinetDCPGetRes(Packet):
    name = "Profinet DCP-Get-ResPDU"
    fields_desc = [
        PacketListField("dcp_blocks", [], DCPResponseBlock),
    ]
bind_layers(ProfinetDCP, ProfinetDCPGetRes, service_type=DCP_SERVICE_TYPE.RESPONSE_SUCCESS, service_id=DCP_SERVICE_ID.GET)

class ProfinetDCPSetReq(Packet):
    name = "Profinet DCP-Set-ReqPDU"
    fields_desc = [
        PacketListField("dcp_blocks", [], DCPSetRequestBlock),
    ]
bind_layers(ProfinetDCP, ProfinetDCPSetReq, service_type=DCP_SERVICE_TYPE.REQUEST, service_id=DCP_SERVICE_ID.SET)

class ProfinetDCPSetRes(Packet):
    name = "Profinet DCP-Set-ResPDU"
    fields_desc = [
        PacketListField("dcp_blocks", [], DCPResponseBlock),
    ]
bind_layers(ProfinetDCP, ProfinetDCPSetRes, service_type=DCP_SERVICE_TYPE.RESPONSE_SUCCESS, service_id=DCP_SERVICE_ID.SET)
#     # calculate the len fields - workaround
    #     ConditionalField(LenField("dcp_block_length", 0),
    #                      lambda pkt: pkt.service_type == 0),

    #     # DCP SET REQUEST #
    #     ConditionalField(ShortEnumField("block_qualifier", 1,
    #                                     BLOCK_QUALIFIERS),
    #                      lambda pkt: pkt.service_id == 4 and
    #                      pkt.service_type == 0),
    #     # (Common) Name Of Station
    #     ConditionalField(
    #         MultipleTypeField(
    #             [
    #                 (StrLenField("name_of_station", "et200sp",
    #                              length_from=lambda x: x.dcp_block_length - 2),
    #                  lambda pkt: pkt.service_id == 4),
    #             ],
    #             StrLenField("name_of_station", "et200sp",
    #                         length_from=lambda x: x.dcp_block_length),
    #         ),
    #         lambda pkt: pkt.service_type == 0 and pkt.option == 2 and
    #         pkt.sub_option == 2
    #     ),
    #     # DCP SET REQUEST #
    #     # MAC
    #     ConditionalField(MACField("mac", "00:00:00:00:00:00"),
    #                      lambda pkt: pkt.service_id == 4 and
    #                      pkt.service_type == 0 and pkt.option == 1 and
    #                      pkt.sub_option == 1),
    #     # IP
    #     ConditionalField(IPField("ip", "192.168.0.2"),
    #                      lambda pkt: pkt.service_id == 4 and
    #                      pkt.service_type == 0 and pkt.option == 1 and
    #                      pkt.sub_option in [2, 3]),
    #     ConditionalField(IPField("netmask", "255.255.255.0"),
    #                      lambda pkt: pkt.service_id == 4 and
    #                      pkt.service_type == 0 and pkt.option == 1 and
    #                      pkt.sub_option in [2, 3]),
    #     ConditionalField(IPField("gateway", "192.168.0.1"),
    #                      lambda pkt: pkt.service_id == 4 and
    #                      pkt.service_type == 0 and pkt.option == 1 and
    #                      pkt.sub_option in [2, 3]),

    #     # Full IP
    #     ConditionalField(FieldListField("dnsaddr", [], IPField("", "0.0.0.0"),
    #                                     count_from=lambda x: 4),
    #                      lambda pkt: pkt.service_id == 4 and
    #                      pkt.service_type == 0 and pkt.option == 1 and
    #                      pkt.sub_option == 3),

    #     # DCP IDENTIFY REQUEST #
    #     # Name of station (handled above)

    #     # Alias name
    #     ConditionalField(StrLenField("alias_name", "et200sp",
    #                                  length_from=lambda x: x.dcp_block_length),
    #                      lambda pkt: pkt.service_id == 5 and
    #                      pkt.service_type == 0 and pkt.option == 2 and
    #                      pkt.sub_option == 6),

    #     # implement further REQUEST fields if needed ....

    #     # DCP RESPONSE BLOCKS #
    #     ConditionalField(
    #         PacketListField("dcp_blocks", [], guess_dcp_block_class,
    #                         length_from=lambda p: p.dcp_data_length),
    #         lambda pkt: pkt.service_type == 1),
    # ]

    # def post_build(self, pkt, pay):
    #     # add padding to ensure min packet length

    #     padding = MIN_PACKET_LENGTH - (len(pkt + pay))
    #     pay += b"\0" * padding

    #     return Packet.post_build(self, pkt, pay)


#bind_layers(ProfinetDCP, Padding)
