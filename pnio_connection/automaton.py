from asyncio import get_running_loop, DatagramProtocol, DatagramTransport
import enum
import logging
import random
import time
import socket
import uuid
from typing import Any, Optional

from scapy.packet import Packet
from scapy.layers.l2 import Ether
from scapy.supersocket import StreamSocket
from scapy.layers.dcerpc import DceRpc4, _DCE_RPC_ERROR_CODES
from .pnio_rpc import Block, ARBlockReq, RPC_IO_OPNUM, IODReadReq, IODWriteReq, PNIOServiceReqPDU, PNIOServiceResPDU
from scapy.automaton import Automaton, ATMT
from scapy.interfaces import resolve_iface
from scapy.all import conf
from .pnio import ProfinetIO, PNIORealTimeCyclicPDU
from .pnio_dcp import (
    ProfinetDCP,
    ProfinetDCPIdentifyReq,
    ProfinetDCPSetReq,
    ProfinetDCPIdentifyRes,
    ProfinetDCPSetRes,
    DCPRequestBlock,
    NameOfStationBlock,
    IPParameterBlock,
    DCP_SERVICE_ID,
    DCP_SERVICE_TYPE,
)

ETHERTYPE_PROFINET=0x8892
MAC_PROFINET_BCAST= "01:0e:cf:00:00:00"

class PNIOClient(Automaton):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, ll=conf.L2socket, **kwargs)

    def parse_args(self, iface, name_of_station, ip, netmask, gateway, *args, **kwargs):
        super().parse_args(*args, iface=iface, type=ETHERTYPE_PROFINET, **kwargs)
        self.name_of_station = name_of_station
        self.ip = ip
        self.netmask = netmask
        self.gateway = gateway
        self.iface = resolve_iface(iface)
        self.src_mac = self.iface.mac

    @ATMT.state(initial=1)
    def IDENTIFY_REQ(self):
        # Discover the device with LLDP
        # https://www.rapid7.com/blog/post/2019/12/09/how-i-shut-down-a-test-factory-with-a-single-layer-2-packet/
        xid = random.randint(0, 65535)
        self.identify_req = (
            Ether(dst=MAC_PROFINET_BCAST, src=self.src_mac)
            / ProfinetIO()
            / ProfinetDCP(
                xid=xid,
                response_delay_factor=1, # max response delay in 10ms increments
            )
            / ProfinetDCPIdentifyReq(
                dcp_blocks=[
                    DCPRequestBlock() / NameOfStationBlock(name_of_station="workshop-caparoc"),
                ]
            )
        )
        self.send(self.identify_req)
        raise self.WAITING_IDENTIFY_REPLY()

    @ATMT.state()
    def WAITING_IDENTIFY_REPLY(self):
        pass

    @ATMT.receive_condition(WAITING_IDENTIFY_REPLY)
    def check_identify_reply(self, pkt):
        if pkt.haslayer(ProfinetDCPIdentifyRes) and pkt[ProfinetDCP].xid == self.identify_req[ProfinetDCP].xid:
            self.dst_mac = pkt[Ether].src
            if ip := pkt.getlayer(IPParameterBlock):
                if ip.ip == self.ip and ip.netmask == self.netmask and ip.gateway == self.gateway:
                    raise self.EXCHANGE_CONFIGURATION()
            raise self.SET_IP()

    @ATMT.state()
    def SET_IP(self):
        xid = random.randint(0, 65535)
        set_ip_req = (
            Ether(dst=self.dst_mac, src=self.src_mac)
            / ProfinetIO()
            / ProfinetDCP(
                xid=xid,
                response_delay_factor=1, # max response delay in 10ms increments
            )
            / ProfinetDCPSetReq(
                dcp_blocks = [
                    DCPSetRequestBlock(block_qualifier=1) / IPParameterBlock(ip=self.ip, netmask=self.netmask, gateway=self.gateway),
                ],
            )
        )
        self.send(identify_req)
        raise self.WAITING_SET_IP_REPLY()

    @ATMT.state()
    def WAITING_SET_IP_REPLY(self):
        pass

    @ATMT.receive_condition(WAITING_SET_IP_REPLY)
    def check_set_ip_reply(self, pkt):
        if pkt.haslayer(ProfinetDCPSetRes) and pkt[ProfinetDCP].xid == self.identify_req[ProfinetDCP].xid:
            raise self.EXCHANGE_CONFIGURATION()

class PNIORPCClient(Automaton):
    def READ(self):
        auuid = 0
        r = (
            DceRpc4(
                flags1=["no_frag_ack", "idempotent"],
                opnum=RPC_IO_OPNUM.ReadImplicit,
            )
            / PNIOServiceReqPDU(blocks=[
                IODReadReq(
                    seqNum=1,
                    ARUUID=auuid,
                    API=0x0,
                    slotNumber=0x0,
                    subslotNumber=2,
                    index=17,
                ),
            ])
        )

class RpcSocket(StreamSocket):
    def __init__(self, dst_host):
        port = socket.getservbyname("profinet-cm")
        self.dst_addr = (dst_host, port)
        self.seqnum = 0
        self.serial_number = 0
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('0.0.0.0', 0)) # Random port
        super().__init__(sock, DceRpc4)

    def send(self, x):
        sx = bytes(x)
        try:
            x.sent_time = time.time()
        except AttributeError:
            pass
        if self.outs:
            return self.outs.sendto(sx, self.dst_addr)
        return 0

    def get_header(self, opnum, seqnum=None):
        if seqnum is None:
            seqnum = self.seqnum
            self.seqnum += 1
        serial_number = self.serial_number
        self.serial_number += 1
        return DceRpc4(
            flags1=["no_frag_ack", "idempotent"],
            opnum=opnum,
            seqnum=seqnum,
            fragnum=0, # TODO: Support fragmentation
            serial_hi=(serial_number >> 8) & 0xFF,
            serial_lo=serial_number & 0xFF
        )

LOGGER = logging.getLogger("profinet")

class DceRpcError(Exception):
    def __init__(self, code):
        self.code = code

    def __str__(self):
        return _DCE_RPC_ERROR_CODES.get(self.code, hex(self.code))

class DceRpcProtocol(DatagramProtocol):
    def __init__(self, dst_host):
        port = socket.getservbyname("profinet-cm")
        self.dst_addr = (dst_host, port)
        self.seqnum = 0
        self.serial_number = 0
        self.pending_requests = dict()
        super().__init__()

    def _get_header(self, opnum, seqnum=None):
        if seqnum is None:
            seqnum = self.seqnum
            self.seqnum += 1
        serial_number = self.serial_number
        self.serial_number += 1
        return DceRpc4(
            flags1=["no_frag_ack", "idempotent"],
            opnum=opnum,
            seqnum=seqnum,
            fragnum=0, # TODO: Support fragmentation
            serial_hi=(serial_number >> 8) & 0xFF,
            serial_lo=serial_number & 0xFF
        )

    async def call_rpc(self, opnum: int, pdu: Packet, object: Optional[uuid.UUID] = None):
        req = self._get_header(opnum)
        if object is not None:
            req.object = object
        req = req / pdu
        fut = get_running_loop().create_future()
        self.pending_requests[req.seqnum] = fut
        LOGGER.debug("sending packet:\n%s", req.show2(dump=True))
        self.transport.sendto(bytes(req), self.dst_addr)
        # TODO: Timeout?
        # TODO: Retries
        res = await fut
        if res.ptype == 2: # response
            return res.payload
        elif res.ptype in (3, 6): # fault, reject
            raise DceRpcError(int.from_bytes(res.payload.load, "little"))
        else:
            raise ValueError("unexpected response type: %s" % (res.ptype,))


    def connection_made(self, transport: DatagramTransport) -> None:
        LOGGER.info("connection made: %s", transport)
        self.transport = transport
        return super().connection_made(transport)
    def datagram_received(self, data: bytes, addr: tuple[str | Any, int]) -> None:
        # TODO: Consider switching to recvmsg
        try:
            pkt = DceRpc4(data)
        except:
            LOGGER.exception("failed to parse packet")
            return
        LOGGER.debug("received packet:\n%s", pkt.show2(dump=True))
        # TODO: Ack?
        # TODO: Error handling?
        # TODO: Check packet type?
        if fut := self.pending_requests.get(pkt.seqnum):
            fut.set_result(pkt)
            del self.pending_requests[pkt.seqnum]
        else:
            LOGGER.warning("received unknown sequence number: %s", pkt.show2(dump=True))

class ERROR_CODE(enum.IntEnum):
    PNIO = 0x81
    RTA_error = 0xCF
    AlarmAck = 0xDA
    IODConnect = 0xDB
    IODRelease = 0xDC
    IOxControl = 0xDD
    IODRead = 0xDE
    IODWrite = 0xDF

class ERROR_DECODE(enum.IntEnum):
    PNIORW = 0x80
    PNIO = 0x81

class PNIORW_ERROR_CODE_1(enum.IntEnum):
    # Application
    READ_ERROR = 0xA0
    WRITE_ERROR = 0xA1
    MODULE_FAILURE = 0xA2
    BUSY = 0xA7
    VERSION_CONFLICT = 0xA8
    FEATURE_NOT_SUPPORTED = 0xA9
    USER_SPECIFIC_1 = 0xAA
    USER_SPECIFIC_2 = 0xAB
    USER_SPECIFIC_3 = 0xAC
    USER_SPECIFIC_4 = 0xAD
    USER_SPECIFIC_5 = 0xAE
    USER_SPECIFIC_6 = 0xAF
    # Access
    INVALID_INDEX = 0xB0
    WRITE_LENGTH_ERROR = 0xB1
    INVALID_SLOT = 0xB2
    TYPE_CONFLICT = 0xB3
    INVALID_AREA = 0xB4
    STATE_CONFLICT = 0xB5
    ACCESS_DENIED = 0xB6
    INVALID_RANGE = 0xB7
    INVALID_PARAMETER = 0xB8
    INVALID_TYPE = 0xB9
    BACKUP = 0xBA
    USER_SPECIFIC_7 = 0xBB
    USER_SPECIFIC_8 = 0xBC
    USER_SPECIFIC_9 = 0xBD
    USER_SPECIFIC_10 = 0xBE
    USER_SPECIFIC_11 = 0xBF
    # Resource
    READ_CONSTRAIN_CONFLICT = 0xC0
    WRITE_CONSTRAIN_CONFLICT = 0xC1
    RESOURCE_BUSY = 0xC2
    RESOURCE_UNAVAILABLE = 0xC3
    USER_SPECIFIC_12 = 0xC8
    USER_SPECIFIC_13 = 0xC9
    USER_SPECIFIC_14 = 0xCA
    USER_SPECIFIC_15 = 0xCB
    USER_SPECIFIC_16 = 0xCC
    USER_SPECIFIC_17 = 0xCD
    USER_SPECIFIC_18 = 0xCE
    USER_SPECIFIC_19 = 0xCF

class PnioRpcError(Exception):
    def __init__(self, status):
        self.status = status
        b = status.to_bytes(4, byteorder='big')
        try:
            self.error_code = ERROR_CODE(b[0])
        except ValueError:
            self.error_code = b[0]
        try:
            self.error_decode = ERROR_DECODE(b[1])
        except ValueError:
            self.error_decode = b[1]
        self.error_code_1 = b[2]
        if self.error_decode == ERROR_DECODE.PNIORW:
            try:
                self.error_code_1 = PNIORW_ERROR_CODE_1(self.error_code_1)
            except ValueError:
                pass
        self.error_code_2 = b[3]

    def __str__(self):
        return f"{self.error_code!r} - {self.error_decode!r} ({self.error_code_1!r} {self.error_code_2!r})"

class PnioRpcProtocol(DceRpcProtocol):
    async def rpc(self, opnum: int, blocks: list[Block], args_max=16696):
        # TODO: Set automatically
        # in big endian, u16 instance, u16 device, u16 vendor
        # VendorID="0x00B0" DeviceID="0x015F"
        object = "dea00000-6c97-11d1-8271-0000015f00b0"
        res = await self.call_rpc(
            opnum=opnum,
            pdu=PNIOServiceReqPDU(args_max=args_max, blocks=blocks),
            object=object,
        )
        if not isinstance(res, PNIOServiceResPDU):
            LOGGER.error("didn't receive a PNIOServiceResPDU:\n%s", res.show2(dump=True))
            raise ValueError("missing PNIOServiceResPDU")
        if res.status != 0:
            raise PnioRpcError(res.status)
        return res.blocks

class ContextManagerProtocol(PnioRpcProtocol):
    def __init__(self, dst_host):
        super().__init__(dst_host=dst_host)
        self.aruuid = 0
        self.session_key = 0

    async def connect(self, cm_mac_addr):
        if self.aruuid:
            raise ValueError("connect while already connected")
        self.session_key += 1
        aruuid = uuid.uuid4()
        ar_block_req = ARBlockReq(
            ARUUID=aruuid,
            SessionKey=self.session_key, # The value of the field SessionKey shall be increased by one for each connect by the CMInitiator.
            CMInitiatorMacAdd=cm_mac_addr,
            # in big endian, the last part is u16 instance, u16 device, u16 vendor
            CMInitiatorObjectUUID="dea00000-6c97-11d1-8271-00000000f000",
            CMInitiatorStationName="py-profinet",
            ARProperties_DeviceAccess=0,
            ARProperties_StartupMode="Legacy", # "Legacy" is Recommended
            ARProperties_ParameterizationServer="CM_Initiator",
        )
        res = await self.rpc(
            opnum=RPC_IO_OPNUM.Connect,
            blocks=[
                ar_block_req,
            ],
        )
        # Success!
        self.aruuid = aruuid
        return res

    async def read(self, slot=0, subslot=0, index=0):
        req = IODReadReq(seqNum=1, ARUUID=self.aruuid, API=0x0, slotNumber=slot, subslotNumber=subslot, index=index)
        return (await self.rpc(opnum=RPC_IO_OPNUM.Read if self.aruuid else RPC_IO_OPNUM.ReadImplicit, blocks=[req]))[0]

    async def write(self, data, slot=0, subslot=0, index=0):
        req = IODWriteReq(seqNum=1, ARUUID=self.aruuid, API=0x0, slotNumber=slot, subslotNumber=subslot, index=index) / data
        return (await self.rpc(opnum=RPC_IO_OPNUM.Write, blocks=[req]))[0]
