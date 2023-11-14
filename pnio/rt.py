from asyncio import Queue, get_running_loop, DatagramProtocol, DatagramTransport, Future
from collections.abc import Callable
from contextlib import asynccontextmanager
import enum
import logging
import random
import time
import socket
import uuid
from typing import Any, Optional, Tuple

from scapy.packet import Packet
from scapy.plist import PacketList
from scapy.layers.l2 import Ether
from scapy.layers.dcerpc import DceRpc4, _DCE_RPC_ERROR_CODES
from .pnio_rpc import RPC_INTERFACE_UUID, Alarm_High, Alarm_Low, AlarmCRBlockReq, Block, ARBlockReq, RPC_IO_OPNUM, ExpectedSubmodule, ExpectedSubmoduleBlockReq, ExpectedSubmoduleDataDescription, ExpectedSubmoduleAPI, IODControlReq, IODReadReq, IODWriteReq, PNIOServiceReqPDU, PNIOServiceResPDU, RealIdentificationDataSubslot, NDREPMapLookupReq
from scapy.interfaces import resolve_iface
from scapy.config import conf
from .pnio import ProfinetIO, PNIORealTimeCyclicPDU
from .pnio_dcp import (
    DeviceIDBlock,
    DeviceInstanceBlock,
    ProfinetDCP,
    ProfinetDCPIdentifyReq,
    ProfinetDCPSetReq,
    ProfinetDCPIdentifyRes,
    ProfinetDCPSetRes,
    DCPRequestBlock,
    DCPSetRequestBlock,
    NameOfStationBlock,
    IPParameterBlock,
    DCP_SERVICE_ID,
    DCP_SERVICE_TYPE,
)
from .rpc import ContextManagerActivity

ETHERTYPE_PROFINET=0x8892
MAC_PROFINET_BCAST= "01:0e:cf:00:00:00"

LOGGER = logging.getLogger("profinet.rt")

class RTProtocol(DatagramProtocol):
    src_mac: bytes
    pending_requests: dict[tuple[str, int], Queue]
    frame_handlers: dict[int, Callable[[ProfinetIO], None]]
    alarm_handlers: dict[tuple[int, int], Callable[[ProfinetIO], None]]

    def __init__(self):
        self.pending_requests = {}
        self.frame_handlers = {
            0xFC01: self._handle_alarm, # Alarm High
            0xFE01: self._handle_alarm, # Alarm Low
        }
        self.alarm_handlers = {}

    def connection_made(self, transport: DatagramTransport) -> None:
        self.transport = transport
        sockname = transport.get_extra_info('sockname')
        self.ifname = sockname[0]
        self.src_mac = sockname[4]
        return super().connection_made(transport)

    async def dcp_req(self, req, dst_mac: str|bytes = MAC_PROFINET_BCAST):
        xid = random.randint(0, 65535)
        pkt = (
            Ether(dst=dst_mac, src=self.src_mac)
            / ProfinetIO()
            / ProfinetDCP(
                xid=xid,
                response_delay_factor=1, # max response delay in 10ms increments
            )
            / req
        )
        queue = Queue()
        try:
            self.pending_requests[("dcp", xid)] = queue
            self.send(pkt)
            while True:
                pkt = await queue.get()
                try:
                    yield pkt
                finally:
                    queue.task_done()
        finally:
            del self.pending_requests[("dcp", xid)]

    async def dcp_req_one(self, req, dst_mac=MAC_PROFINET_BCAST):
        # TODO: Is it sufficient to just wait for the iterator to be GC'd, or
        # do we need to explicitly aclose it?
        async for res in self.dcp_req(req, dst_mac):
            return res

    async def dcp_identify(self, name_of_station: str) -> ProfinetDCP:
        return await self.dcp_req_one(
            ProfinetDCPIdentifyReq(
                dcp_blocks=[
                    DCPRequestBlock() / NameOfStationBlock(name_of_station=name_of_station),
                ]
            ),
        )

    async def dcp_set_ip(self, mac, ip, netmask, gateway):
        return await self.dcp_req_one(
            ProfinetDCPSetReq(
                dcp_blocks = [
                    DCPSetRequestBlock(block_qualifier=1) / IPParameterBlock(ip=ip, netmask=netmask, gateway=gateway),
                ],
            ),
            dst_mac=mac,
        )

    def send(self, pkt: Packet):
        pkt.sent_time = pkt.time = time.time()
        LOGGER.debug("sending packet:\n%s", pkt.show2(dump=True))
        if conf.debug_match:
            debug.sent.append(pkt)
        self.transport.sendto(bytes(pkt), (self.ifname, ETHERTYPE_PROFINET))

    def datagram_received(self, data: bytes, src_addr: tuple[str | Any, int]) -> None:
        # TODO: Consider switching to recvmsg
        try:
            pkt = Ether(data)
        except:
            LOGGER.exception("failed to parse packet")
            return
        pkt.time = time.time()
        LOGGER.debug("received packet:\n%s", pkt.show2(dump=True))
        if conf.debug_match:
            debug.recv.append(pkt)
        # TODO: Do something with packet
        key = None
        if pkt.haslayer(ProfinetDCP):
            xid = pkt[ProfinetDCP].xid
            key = ("dcp", xid)
        elif pkt.haslayer(ProfinetIO):
            frame_id = pkt[ProfinetIO].frameID
            if handler := self.frame_handlers.get(frame_id):
                handler(pkt)
        if key and key in self.pending_requests:
            self.pending_requests[key].put_nowait(pkt)

    def register_frame_handler(self, frame_id: int, handler: Callable[[ProfinetIO], None]):
        self.frame_handlers[frame_id] = handler

    def register_alarm_handler(self, src_endpoint: int, dst_endpoint: int, handler: Callable[[ProfinetIO], None]):
        self.alarm_handlers[(src_endpoint, dst_endpoint)] = handler

    def _handle_alarm(self, pkt: ProfinetIO):
        endpoints = (pkt.AlarmSrcEndpoint, pkt.AlarmDstEndpoint)
        if handler := self.alarm_handlers.get(endpoints):
            handler(pkt)

    def send_cyclic_data_frame(self, data: bytes, frame_id: int, dst_mac: str | bytes, cycle_counter: int | None):
        if cycle_counter is None:
            # Unit is steps of 31.25 µs
            cycle_counter = int(time.time() * 32000)
        self.send_frame(
            PNIORealTimeCyclicPDU(
                cycleCounter=cycle_counter & 0xFFFF,
                data=[data],
            ),
            frame_id=frame_id,
            dst_mac=dst_mac,
        )

    def send_frame(self, data: bytes | Packet, frame_id: int, dst_mac: str | bytes):
        pkt = (
            Ether(dst=dst_mac, src=self.src_mac, type=ETHERTYPE_PROFINET)
            / ProfinetIO(frameID=frame_id)
            / data
        )
        self.send(pkt)


class debug:
    recv = PacketList([], "Received")
    sent = PacketList([], "Sent")

async def create_rt_endpoint(ifname, loop=None) -> RTProtocol:
    if loop is None:
        loop = get_running_loop()
    sock = socket.socket(
        family=socket.AF_PACKET,
        type=socket.SOCK_RAW,
        proto=ETHERTYPE_PROFINET,
    )
    sock.bind((ifname, ETHERTYPE_PROFINET))
    sock.setblocking(False)
    mac_address = sock.getsockname()[4]
    LOGGER.info("Creating RT endpoint on %s (%s)", ifname, mac_address.hex())
    protocol = RTProtocol()
    waiter = loop.create_future()
    # N.B. asyncio.create_datagram_endpoint checks to make sure the type is SOCK_DGRAM.
    # Even though SOCK_RAW would work fine, we have to call the underlying method to sidestep that check.
    transport = loop._make_datagram_transport(
        sock, protocol, None, waiter)
    try:
        await waiter
    except:
        transport.close()
        raise
    return protocol
