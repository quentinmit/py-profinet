from asyncio import AbstractEventLoop, Future, Event, Queue, get_running_loop, DatagramProtocol, DatagramTransport
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from weakref import WeakValueDictionary
import enum
import logging
import time
import socket
import uuid
from typing import Any, Optional, Tuple

import async_timeout
from scapy.packet import Packet
from scapy.plist import PacketList
from scapy.layers.dcerpc import DceRpc4, _DCE_RPC_ERROR_CODES
from .pnio_rpc import RPC_INTERFACE_UUID, AlarmCRBlockReq, AlarmCRBlockRes, Block, ARBlockReq, RPC_IO_OPNUM, ExpectedSubmodule, ExpectedSubmoduleBlockReq, ExpectedSubmoduleDataDescription, ExpectedSubmoduleAPI, IOCRBlockRes, IODControlReq, IODControlRes, IODReadReq, IODWriteReq, PNIOServiceReqPDU, PNIOServiceResPDU, RealIdentificationDataSubslot, NDREPMapLookupReq
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
    pending_requests: dict[tuple[uuid.UUID, int], Future]
    registered_handlers: dict[tuple[uuid.UUID, uuid.UUID], Callable[[DceRpc4], Awaitable[Packet]]]
    instance: int

    def __init__(self):
        self.pending_requests = dict()
        self.registered_handlers = dict()
        self.instance = 0
        super().__init__()

    def register_handler(self, object: uuid.UUID, interface: uuid.UUID, handler: Callable[[DceRpc4], Awaitable[Packet]]):
        self.registered_handlers[object, interface] = handler

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
        key = (pkt.act_id, pkt.seqnum)
        if fut := self.pending_requests.get(key):
            fut.set_result(pkt)
            del self.pending_requests[key]
        elif pkt.ptype == 0: # Request
            get_running_loop().create_task(self._handle_request(pkt, src_addr))
        else:
            LOGGER.warning("received unknown sequence number: %s", pkt.show2(dump=True))

    async def _handle_request(self, pkt: DceRpc4, src_addr: tuple[str | Any, int]):
        out = DceRpc4(
            ptype="reject", # "fault" is also an option
            flags1=["last_frag", "no_frag_ack"],
            serial_hi=pkt.serial_hi,
            object=pkt.object,
            if_id=pkt.if_id,
            act_id=pkt.act_id,
            if_vers=pkt.if_vers,
            seqnum=0, # TODO
            opnum=pkt.opnum,
            fragnum=0, # TODO: Support fragmentation
            serial_lo=pkt.serial_lo,
        )
        try:
            assert "idempotent" in pkt.flags1, "can only handle idempotent requests"
            handler = self.registered_handlers[(pkt.object, pkt.if_id)]
            res = await handler(pkt)
            out.ptype = "response"
            out = out / res
        except:
            logging.exception("Failed to handle incoming request")
        self.send(out, src_addr)

    async def call_rpc(self, req: DceRpc4, dst_addr: tuple[str, int], timeout: float|None = 1):
        fut = get_running_loop().create_future()
        try:
            self.pending_requests[(req.act_id, req.seqnum)] = fut
            self.send(req, dst_addr)
            with async_timeout.timeout(timeout):
                # TODO: Retries
                res = await fut
        finally:
            fut.cancel()
            if self.pending_requests[(req.act_id, req.seqnum)] == fut:
                del self.pending_requests[(req.act_id, req.seqnum)]
        if res.ptype == 2: # response
            return res.payload
        elif res.ptype in (3, 6): # fault, reject
            raise DceRpcError(int.from_bytes(res.payload.load, "little"))
        else:
            raise ValueError("unexpected response type: %s" % (res.ptype,))

    def send(self, pkt: DceRpc4, dst_addr: tuple[str, int]):
        LOGGER.debug("sending packet:\n%s", pkt.show2(dump=True))
        pkt.sent_time = pkt.time = time.time()
        if conf.debug_match:
            from scapy.layers.inet import IP, UDP
            src_addr = self.transport.get_extra_info('sockname', (None, None))
            p = (
                IP(src=src_addr[0], dst=dst_addr[0])
                / UDP(sport=src_addr[1], dport=dst_addr[1])
                / pkt
            )
            p.time = pkt.time
            debug.sent.append(p)
        self.transport.sendto(bytes(pkt), dst_addr)


async def create_rpc_endpoint(port: int = socket.getservbyname("profinet-cm"), loop: AbstractEventLoop | None = None) -> DceRpcProtocol:
    if loop is None:
        loop = get_running_loop()
    _, protocol = await loop.create_datagram_endpoint(
        protocol_factory=DceRpcProtocol,
        local_addr=('0.0.0.0', port),
        family=socket.AF_INET,
    )
    return protocol

class Activity:
    def __init__(self, protocol: DceRpcProtocol, dst_host: str):
        self.protocol = protocol
        self.dst_host = dst_host
        port = socket.getservbyname("profinet-cm")
        self.default_port = port
        self.seqnum = 0
        self.activity_uuid = uuid.uuid4()
        self.serial_number = 0
        self.endpoints_by_interface = None


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
        dst_addr = await self._get_addr_for_interface(req.if_id)
        return await self.protocol.call_rpc(req, dst_addr=dst_addr)

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

class PnioRpcActivity(Activity):
    def __init__(self, protocol, dst_host, vendor_id, device_id, instance=1):
        super().__init__(protocol=protocol, dst_host=dst_host)
        self.object = create_pn_uuid(vendor_id=vendor_id, device_id=device_id, instance=instance)

    async def rpc(self, opnum: int, blocks: list[Block], args_max=32832): #16696):
        res = await self.call_rpc(
            opnum=opnum,
            pdu=PNIOServiceReqPDU(
                args_max=args_max,
                max_count=args_max,
                blocks=blocks),
            object=self.object,
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

def create_pn_uuid(vendor_id, device_id, instance=0):
    # in big endian, the last part is u16 instance, u16 device, u16 vendor
    return uuid.UUID(fields=(
        0xdea00000,
        0x6c97,
        0x11d1,
        0x82, 0x71,
        (instance << 32) | (device_id << 16) | vendor_id
    ))

class Association:
    aruuid: uuid.UUID
    session_key: int
    application_ready: Event
    _connect_req: list[Packet]
    _connect_res: list[Packet]

    def __init__(self, activity, aruuid=None, session_key=None):
        self.activity = activity
        if not session_key:
            session_key = activity.session_key
            activity.session_key += 1
        self.session_key = session_key
        if not aruuid:
            aruuid = uuid.uuid4()
        self.aruuid = aruuid
        self.application_ready = Event()
        self._connect_req = []
        self._connect_res = []

    async def _connect(self, cm_mac_addr, easy_supervisor=False, alarm_reference=1, extra_blocks=[]):
        ar_block_req = ARBlockReq(
            ARUUID=self.aruuid,
            SessionKey=self.session_key, # The value of the field SessionKey shall be increased by one for each connect by the CMInitiator.
            CMInitiatorMacAdd=cm_mac_addr,
            CMInitiatorObjectUUID=self.activity.cm_object_uuid,
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
            alarm_block_req = AlarmCRBlockReq(
                LocalAlarmReference=alarm_reference,
            )
            blocks.append(alarm_block_req)
        blocks.extend(extra_blocks)
        self._connect_req = blocks
        res = await self.activity.rpc(
            opnum=RPC_IO_OPNUM.Connect,
            blocks=blocks,
        )
        # Success!
        self._connect_res = res
        return res

    async def _release(self):
        req = IODControlReq(ARUUID=self.aruuid, SessionKey=self.session_key, ControlCommand_Release=1)
        # Spec says a successful release should return back the request with
        # ControlCommand_Done=1, but it appears to return nothing.
        return (await self.activity.rpc(opnum=RPC_IO_OPNUM.Release, blocks=[req]))

    async def read(self, slot=0, subslot=0, index=0):
        req = IODReadReq(seqNum=1, ARUUID=self.aruuid, API=0x0, slotNumber=slot, subslotNumber=subslot, index=index, recordDataLength=0x8000)
        blocks = await self.activity.rpc(opnum=RPC_IO_OPNUM.Read, blocks=[req])
        return blocks[1:]

    async def write(self, data, slot=0, subslot=0, index=0):
        req = IODWriteReq(seqNum=1, ARUUID=self.aruuid, API=0x0, slotNumber=slot, subslotNumber=subslot, index=index) / data
        return (await self.activity.rpc(opnum=RPC_IO_OPNUM.Write, blocks=[req]))[0]

    async def parameter_end(self):
        req = IODControlReq(
            ARUUID=self.aruuid,
            SessionKey=self.session_key,
            ControlCommand_PrmEnd=0x0001,
        )
        return await self.activity.rpc(opnum=RPC_IO_OPNUM.Control, blocks=[req])

    @property
    def local_alarm_reference(self) -> int|None:
        for block in self._connect_req:
            if isinstance(block, AlarmCRBlockReq):
                return block.LocalAlarmReference

    @property
    def remote_alarm_reference(self) -> int|None:
        for block in self._connect_res:
            if isinstance(block, AlarmCRBlockRes):
                return block.LocalAlarmReference

    @property
    def input_frame_ids(self) -> list[int]:
        return [block.FrameID for block in self._connect_res if isinstance(block, IOCRBlockRes) and block.IOCRType == 1]

class ContextManagerActivity(PnioRpcActivity):
    def __init__(self, protocol, dst_host, vendor_id, device_id, instance=1):
        super().__init__(protocol=protocol, dst_host=dst_host, vendor_id=vendor_id, device_id=device_id, instance=instance)
        self.session_key = 1
        self.cm_object_uuid = create_pn_uuid(vendor_id=0xf000, device_id=0, instance=protocol.instance)
        self.associations = WeakValueDictionary()
        protocol.instance += 1
        protocol.register_handler(object=self.cm_object_uuid, interface=RPC_INTERFACE_UUID["UUID_IO_ControllerInterface"], handler=self._handle_request)

    async def _handle_request(self, pkt: Packet) -> Packet:
        if isinstance(pkt.payload, PNIOServiceReqPDU):
            req = pkt.payload.blocks[0]
            if isinstance(req, IODControlReq) and req.ControlCommand_ApplicationReady:
                if assoc := self.associations.get((req.ARUUID, req.SessionKey)):
                    if assoc.application_ready.is_set():
                        LOGGER.warning("ApplicationReady received for (%s, %d) but association was already ready", req.ARUUID, req.SessionKey)
                    assoc.application_ready.set()
                # TODO: Check and dispatch to Association using req.ARUUID
                return PNIOServiceResPDU(
                    blocks=[IODControlRes(
                        block_type="IOXBlockRes_connect",
                        ARUUID=req.ARUUID,
                        SessionKey=req.SessionKey,
                        ControlCommand_Done=1,
                    )],
                )
        raise NotImplementedError("unknown request")

    @asynccontextmanager
    async def connect(self, aruuid=None, session_key=None, **kwargs):
        assoc = Association(self, aruuid=aruuid, session_key=session_key)
        self.associations[(assoc.aruuid, assoc.session_key)] = assoc
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

