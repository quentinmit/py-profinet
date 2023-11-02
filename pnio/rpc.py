from asyncio import get_running_loop, DatagramProtocol, DatagramTransport
from contextlib import asynccontextmanager
import enum
import logging
import time
import socket
import uuid
from typing import Any, Optional, Tuple

from scapy.packet import Packet
from scapy.plist import PacketList
from scapy.layers.dcerpc import DceRpc4, _DCE_RPC_ERROR_CODES
from .pnio_rpc import RPC_INTERFACE_UUID, AlarmCRBlockReq, Block, ARBlockReq, RPC_IO_OPNUM, ExpectedSubmodule, ExpectedSubmoduleBlockReq, ExpectedSubmoduleDataDescription, ExpectedSubmoduleAPI, IODControlReq, IODReadReq, IODWriteReq, PNIOServiceReqPDU, PNIOServiceResPDU, RealIdentificationDataSubslot, NDREPMapLookupReq
from scapy.config import conf

LOGGER = logging.getLogger("profinet.rpc")

class debug:
    recv = PacketList([], "Received")
    sent = PacketList([], "Sent")

class DceRpcError(Exception):
    def __init__(self, code):
        self.code = code

    def __str__(self):
        return _DCE_RPC_ERROR_CODES.get(self.code, hex(self.code))

PF_CMRPC_MUST_RECV_FRAG_SIZE = 1464

class DceRpcProtocol(DatagramProtocol):
    def __init__(self, dst_host):
        self.dst_host = dst_host
        port = socket.getservbyname("profinet-cm")
        self.default_port = port
        self.seqnum = 0
        self.activity_uuid = uuid.uuid4()
        self.serial_number = 0
        self.pending_requests = dict()
        self.endpoints_by_interface = None
        super().__init__()

    def _get_header(self, opnum, seqnum=None):
        if seqnum is None:
            seqnum = self.seqnum
            self.seqnum += 1
        serial_number = self.serial_number
        self.serial_number += 1
        return DceRpc4(
            flags1=["no_frag_ack", "idempotent"],
            act_id=self.activity_uuid,
            opnum=opnum,
            seqnum=seqnum,
            fragnum=0, # TODO: Support fragmentation
            serial_hi=(serial_number >> 8) & 0xFF,
            serial_lo=serial_number & 0xFF
        )

    async def list_endpoints(self):
        handle_attribute = 0
        handle_uuid = uuid.UUID(int=0)
        endpoints = []
        while True:
            res = await self.call_rpc(
                opnum=2, pdu=NDREPMapLookupReq(
                    InterfaceUUID=RPC_INTERFACE_UUID["UUID_IO_DeviceInterface"],
                    EntryHandleAttribute=handle_attribute,
                    EntryHandleUUID=handle_uuid,
                ),
            )
            if res.Status == 0x16c9a0d6:
                return endpoints
            endpoints.extend(res.Entries)
            handle_attribute, handle_uuid = res.EntryHandleAttribute, res.EntryHandleUUID

    async def _get_addr_for_interface(self, if_id: uuid.UUID) -> Tuple[str, int]:
        if self.endpoints_by_interface is None:
            # N.B. By starting with a blank dict, the initial load will do
            # call_rpc -> _get_addr_for_interface -> call_rpc ->
            # _get_addr_for_interface -> return default
            self.endpoints_by_interface = dict()
            for entry in await self.list_endpoints():
                self.endpoints_by_interface[
                    entry.Tower.Floors[0].UUID
                ] = (entry.Tower.Floors[4].IP, entry.Tower.Floors[3].Port)
        return self.endpoints_by_interface.get(if_id, (self.dst_host, self.default_port))

    async def call_rpc(self, opnum: int, pdu: Packet, object: Optional[uuid.UUID] = None):
        req = self._get_header(opnum)
        if object is not None:
            req.object = object
        req = req / pdu
        assert len(req) <= PF_CMRPC_MUST_RECV_FRAG_SIZE
        fut = get_running_loop().create_future()
        try:
            self.pending_requests[req.seqnum] = fut
            dst_addr = await self._get_addr_for_interface(req.if_id)
            LOGGER.debug("sending packet:\n%s", req.show2(dump=True))
            req.sent_time = req.time = time.time()
            if conf.debug_match:
                from scapy.layers.inet import IP, UDP
                src_addr = self.transport.get_extra_info('sockname', (None, None))
                p = (
                    IP(src=src_addr[0], dst=dst_addr[0])
                    / UDP(sport=src_addr[1], dport=dst_addr[1])
                    / req
                )
                p.time = req.time
                debug.sent.append(p)
            self.transport.sendto(bytes(req), dst_addr)
            # TODO: Timeout?
            # TODO: Retries
            res = await fut
        finally:
            fut.cancel()
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
    def datagram_received(self, data: bytes, src_addr: tuple[str | Any, int]) -> None:
        # TODO: Consider switching to recvmsg
        try:
            pkt = DceRpc4(data)
        except:
            LOGGER.exception("failed to parse packet")
            return
        pkt.time = time.time()
        LOGGER.debug("received packet:\n%s", pkt.show2(dump=True))
        if conf.debug_match:
            from scapy.layers.inet import IP, UDP
            dst_addr = self.transport.get_extra_info('sockname', (None, None))
            p = (
                IP(src=src_addr[0], dst=dst_addr[0])
                / UDP(sport=src_addr[1], dport=dst_addr[1])
                / pkt
            )
            p.time = pkt.time
            debug.recv.append(p)
        # TODO: Ack?
        # TODO: Error handling?
        # TODO: Check packet type?
        # TODO: Handle multiple response packets?
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
    async def rpc(self, opnum: int, blocks: list[Block], args_max=32832): #16696):
        # TODO: Set automatically
        # in big endian, u16 instance, u16 device, u16 vendor
        # VendorID="0x00B0" DeviceID="0x015F"
        object = "dea00000-6c97-11d1-8271-0001015f00b0"
        res = await self.call_rpc(
            opnum=opnum,
            pdu=PNIOServiceReqPDU(
                args_max=args_max,
                max_count=args_max,
                blocks=blocks),
            object=object,
        )
        if not isinstance(res, PNIOServiceResPDU):
            LOGGER.error("didn't receive a PNIOServiceResPDU:\n%s", res.show2(dump=True))
            raise ValueError("missing PNIOServiceResPDU")
        if res.status != 0:
            raise PnioRpcError(res.status)
        return res.blocks

# 3.2.3.7 Coding of the field SendSeqNum
# This field shall be coded as data type Unsigned16 with the following values:
# Hexadecimal (0x0000 – 0x7FFF)
#   contains a valid SendSeqNum of a Data-RTA-PDU
#   This field contains the number of the Data-RTA-PDU. The first issued Data-RTA-PDU shall contain the SendSeqNum 0. The incrementing and comparison of this number is done using the modulo 215 operation.
# Hexadecimal (0xFFFE, 0xFFFF)
#   These values are used synchronize sender and receiver after esablishment of the application relationship. The value 0xFFFF indicates the first Data-RTA-PDU. The value 0xFFFE indicates that there was no reception of a Data-RTA-PDU before. These values are not valid to indicate user data.
#   NOTE The first Data-RTA-PDU sets SendSeqNum=0xFFFF and AckSeqNum=0xFFFE. It is acknowledged with SendSeqNum=0xFFFE and AckSeqNum=0xFFFF. The second Data-RTA-PDU sets SendSeqNum=0 and AckSeqNum=0xFFFE. The synchronization is necessary because the acyclic protocol does not define any connection monitoring.
# 3.2.3.8 Coding of the field AckSeqNum
# This field shall be coded as data type Unsigned16 with the following values:
# Hexadecimal (0x0000 – 0x7FFF)
#  contains a valid AckSeqNum
#  This field contains the number of the Data-RTA-PDU that is expected to be acknowledged or wich is acknowledged.
# Hexadecimal (0xFFFF, 0xFFFE)
#  contains a initial AckSeqNum
#  The value 0xFFFE indicates the there was no Data-RTA-PDU received before. The value 0xFFFF indicates acknowledges the reception of the first Data-RTA-PDU.

class Association:
    def __init__(self, protocol):
        self.protocol = protocol
        self.session_key = protocol.session_key
        protocol.session_key += 1
        self.aruuid = uuid.uuid4()

    async def _connect(self, cm_mac_addr, easy_supervisor=False, extra_blocks=[]):
        ar_block_req = ARBlockReq(
            ARUUID=self.aruuid,
            SessionKey=self.session_key, # The value of the field SessionKey shall be increased by one for each connect by the CMInitiator.
            CMInitiatorMacAdd=cm_mac_addr,
            # in big endian, the last part is u16 instance, u16 device, u16 vendor
            CMInitiatorObjectUUID="dea00000-6c97-11d1-8271-006400f9002a", # FIXME: Needed?
            #CMInitiatorObjectUUID="dea00000-6c97-11d1-8271-00000000f000",
            CMInitiatorStationName="py-profinet",
            CMInitiatorActivityTimeoutFactor=1000,
            ARProperties_StartupMode="Legacy", # "Legacy" is Recommended
            ARProperties_ParameterizationServer="CM_Initiator",
        )
        if easy_supervisor:
            ar_block_req.ARType="IOSAR"
            ar_block_req.ARProperties_DeviceAccess=1
        blocks = [ar_block_req]
        if not easy_supervisor:
            # TODO: Configure alarm block?
            alarm_block_req = AlarmCRBlockReq()
            blocks.append(alarm_block_req)
        blocks.extend(extra_blocks)
        res = await self.protocol.rpc(
            opnum=RPC_IO_OPNUM.Connect,
            blocks=blocks,
        )
        # Success!
        return res

    async def _release(self):
        req = IODControlReq(ARUUID=self.aruuid, SessionKey=self.session_key, ControlCommand_Release=1)
        # Spec says a successful release should return back the request with
        # ControlCommand_Done=1, but it appears to return nothing.
        return (await self.protocol.rpc(opnum=RPC_IO_OPNUM.Release, blocks=[req]))

    async def read(self, slot=0, subslot=0, index=0):
        req = IODReadReq(seqNum=1, ARUUID=self.aruuid, API=0x0, slotNumber=slot, subslotNumber=subslot, index=index, recordDataLength=0x8000)
        blocks = await self.protocol.rpc(opnum=RPC_IO_OPNUM.Read, blocks=[req])
        return blocks[1:]

    async def write(self, data, slot=0, subslot=0, index=0):
        req = IODWriteReq(seqNum=1, ARUUID=self.aruuid, API=0x0, slotNumber=slot, subslotNumber=subslot, index=index) / data
        return (await self.protocol.rpc(opnum=RPC_IO_OPNUM.Write, blocks=[req]))[0]

class ContextManagerProtocol(PnioRpcProtocol):
    def __init__(self, dst_host):
        super().__init__(dst_host=dst_host)
        self.aruuid = 0
        self.session_key = 1

    @asynccontextmanager
    async def connect(self, **kwargs):
        assoc = Association(self)
        await assoc._connect(**kwargs)
        try:
            yield assoc
        finally:
            await assoc._release()

    async def read_implicit(self, slot=0, subslot=0, index=0):
        req = IODReadReq(seqNum=1, ARUUID=0, API=0x0, slotNumber=slot, subslotNumber=subslot, index=index, recordDataLength=0x8000)
        blocks = await self.rpc(opnum=RPC_IO_OPNUM.ReadImplicit, blocks=[req])
        return blocks[1:]

    async def generate_expected_submodules(self):
        id_data = (await self.read_implicit(0, 0, 0xF000))[0]
        blocks = []
        for api in id_data.APIs:
            for slot in api.Slots:
                submodules = []
                for subslot in slot.Subslots or [RealIdentificationDataSubslot(
                        SubslotNumber=1,
                        SubmoduleIdentNumber=0,
                )]:
                    submodules.append(ExpectedSubmodule(
                        SubslotNumber=subslot.SubslotNumber,
                        SubmoduleIdentNumber=subslot.SubmoduleIdentNumber,
                        SubmoduleProperties_Type="INPUT_OUTPUT",
                        DataDescription=[
                            ExpectedSubmoduleDataDescription(
                                DataDescription="Input",
                                LengthIOCS=1,
                                LengthIOPS=1,
                                SubmoduleDataLength=0,
                            ),
                            ExpectedSubmoduleDataDescription(
                                DataDescription="Output",
                                LengthIOCS=1,
                                LengthIOPS=1,
                                SubmoduleDataLength=0,
                            ),
                        ],
                    ))
                blocks.append(ExpectedSubmoduleBlockReq(
                    NumberOfAPIs=1,
                    APIs=[
                        ExpectedSubmoduleAPI(
                            SlotNumber=slot.SlotNumber,
                            ModuleIdentNumber=slot.ModuleIdentNumber,
                            Submodules=submodules,
                        ),
                    ],
                ))
        return blocks

