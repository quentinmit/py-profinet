from contextlib import asynccontextmanager
import asyncio
from dataclasses import dataclass, field
import logging
from collections.abc import AsyncGenerator, Awaitable, Callable
import struct
from typing import Optional
import uuid

from .pnio import PNIORealTime_IOxS, PNIORealTimeCyclicDefaultRawData, ProfinetIO

from .config import ConfigReader
from .rpc import Association, ContextManagerActivity, DceRpcProtocol, create_rpc_endpoint
from .rt import RTProtocol, create_rt_endpoint
from .pnio_dcp import DeviceInstanceBlock, IPParameterBlock, DeviceIDBlock
from .pnio_rpc import Alarm_High, Alarm_Low, IOCRBlockReq

from scapy.layers.l2 import Ether
from scapy.utils import hexdump


LOGGER = logging.getLogger("profinet.controller")


def cycle_count() -> int:
    return int(asyncio.get_running_loop().time() * 32000)


@dataclass
class Subslot:
    input_data: dict[str, int | None]
    output_data: dict[str, int | None]
    input_iops: PNIORealTime_IOxS = field(default_factory=lambda: PNIORealTime_IOxS(b"\0"))
    output_iocs: PNIORealTime_IOxS = field(default_factory=lambda: PNIORealTime_IOxS(b"\0"))


@dataclass
class Slot:
    subslots: dict[int, Subslot]


class ProfinetDevice:
    rt: RTProtocol
    rpc: DceRpcProtocol
    name_of_station: str
    alarm_reference: int

    aruuid: uuid.UUID
    session_key: int
    slots: dict[int, Slot]
    connected: asyncio.Event
    _listeners: set[asyncio.Event]

    mac: Optional[str | bytes]
    send_seq_num: int|None
    ack_seq_num: int|None

    def __init__(self, rt: RTProtocol, rpc: DceRpcProtocol, name_of_station: str, alarm_reference: int):
        self.rt = rt
        self.rpc = rpc
        self.name_of_station = name_of_station
        self.alarm_reference = alarm_reference

        self.aruuid = uuid.uuid4()
        self.session_key = 1
        self.slots = {}
        self._listeners = set()

        self.mac = None
        self.send_seq_num = self.ack_seq_num = None

    @asynccontextmanager
    async def _connect(self, extra_blocks=[]):
        # Locate device with DCP
        pkt = await self.rt.dcp_identify(self.name_of_station)
        mac = pkt[Ether].src
        # TODO: Set the IP if it's not already set correctly.
        #if ipb := pkt.getlayer(IPParameterBlock):
        #    if not (ipb.ip == ip and ipb.netmask == netmask and ipb.gateway == gateway):
        #        await rt.dcp_set_ip(mac, ip, netmask, gateway)
        ib = pkt[DeviceInstanceBlock]
        instance = (ib.device_instance_high << 8) | ib.device_instance_low
        cmrpc = ContextManagerActivity(
            protocol=self.rpc,
            dst_host=pkt[IPParameterBlock].ip,
            vendor_id=pkt[DeviceIDBlock].vendor_id,
            device_id=pkt[DeviceIDBlock].device_id,
            instance=instance,
        )
        session_key = self.session_key
        self.session_key += 1
        async with cmrpc.connect(
                aruuid=self.aruuid,
                session_key=session_key,
                cm_mac_addr=self.rt.src_mac,
                alarm_reference=self.alarm_reference,
                extra_blocks=extra_blocks,
        ) as assoc:
            self.mac = mac
            self.send_seq_num = self.ack_seq_num = None
            yield assoc

    async def _reconnect_task(self):
        while True:
            async with self._connect() as assoc:
                self.connected.set()
                disconnect_fut = asyncio.get_running_loop().create_future()
                try:
                    # TODO: Watchdog task
                    await disconnect_fut
                finally:
                    self.connected.clear()

    def _handle_alarm(self, pkt: ProfinetIO):
        LOGGER.warn("Got alarm:\n%s", pkt.show(dump=True))
        send_seq_num = self.send_seq_num
        if send_seq_num is None:
            send_seq_num = 0xFFFE
        self.ack_seq_num = pkt.SendSeqNum
        self.rt.send_frame(
            frame_id=pkt.frameID,
            data=Alarm_Low(
                AlarmDstEndpoint=pkt.AlarmSrcEndpoint,
                AlarmSrcEndpoint=pkt.AlarmDstEndpoint,
                PDUTypeType="RTA_TYPE_ACK",
                AckSeqNum=self.ack_seq_num,
                SendSeqNum=send_seq_num,
            ),
            dst_mac=self.mac,
        )

    def _signal_update(self):
        for l in self._listeners:
            l.set()

    @property
    async def updates(self):
        e = asyncio.Event()
        self._listeners.add(e)
        try:
            while True:
                await e.wait()
                e.clear()
                yield self.slots
        finally:
            self._listeners.remove(e)


class ProfinetDeviceConfig(ProfinetDevice):
    config: ConfigReader

    def __init__(self, rt: RTProtocol, rpc: DceRpcProtocol, config: ConfigReader, alarm_reference: int):
        super().__init__(
            rt=rt,
            rpc=rpc,
            name_of_station=config.config["name_of_station"],
            alarm_reference=alarm_reference,
        )
        self.config = config
        for slot in self.config.slots:
            out_subslots = {}
            for subslot in slot.subslots:
                out_subslots[subslot.subslot] = Subslot(
                    input_data={
                        data_item.name: None
                        for data_item in subslot.submodule.input_data
                    },
                    output_data={
                        data_item.name: None
                        for data_item in subslot.submodule.output_data
                    },
                )
            self.slots[slot.slot] = Slot(
                subslots=out_subslots,
            )

    @asynccontextmanager
    async def _connect(self) -> AsyncGenerator[Association, None]:
        async with super()._connect(extra_blocks=self.config.connect_blocks) as assoc:
            self._register_frames(assoc)
            # TODO: Use IODWriteMultipleReq?
            for slot, subslot, index, value in self.config.parameter_values:
                await assoc.write(data=value, slot=slot, subslot=subslot, index=index)
            await assoc.parameter_end()
            # TODO: Await ApplicationReady
            yield assoc

    async def _cyclic_data_task(self, cr: IOCRBlockReq):
        cycle_interval = cr.SendClockFactor * cr.ReductionRatio
        LOGGER.debug("Starting cyclic data for output frame 0x%04x every 0x%04x cycles", cr.FrameID, cycle_interval)
        while True:
            now = cycle_count()
            next_cycle_count = ((now // cycle_interval + 1) * cr.ReductionRatio + cr.Phase) * cr.SendClockFactor
            LOGGER.debug("Current cycle counter %d, next cycle counter %d", now, next_cycle_count)
            await asyncio.sleep((next_cycle_count - now) / 32000)
            data = bytearray(self.config.output_frame_size)
            for slot in self.config.slots:
                for subslot in slot.subslots:
                    if subslot.output_data_offset is None:
                        continue
                    format, field_names = subslot.output_fields
                    try:
                        struct.pack_into(
                            format,
                            data,
                            subslot.output_data_offset,
                            *[self.slots[subslot.slot].subslots[subslot.subslot].output_data[name] for name in field_names]
                        )
                    except struct.error:
                        LOGGER.warn("Output data not ready yet")
                    else:
                        struct.pack_into(
                            ">B",
                            data,
                            subslot.output_iops_offset,
                            0x80, # TODO: Use PNIORealTime_IOxS
                        )

            LOGGER.debug("Output\n%s", hexdump(data, dump=1))
            if self.mac:
                self.rt.send_cyclic_data_frame(
                    data=data,
                    frame_id=cr.FrameID,
                    dst_mac=self.mac,
                    cycle_counter=next_cycle_count,
                )

    def _register_frames(self, assoc: Association):
        self.rt.register_alarm_handler(
            src_endpoint=assoc.remote_alarm_reference,
            dst_endpoint=assoc.local_alarm_reference,
            handler=self._handle_alarm,
        )
        input_format, input_fields = self.config.input_struct
        def _handle_input_frame(frame: ProfinetIO):
            data = frame[PNIORealTimeCyclicDefaultRawData].data
            LOGGER.debug("Input\n%s", hexdump(data, dump=1))
            values = struct.unpack_from(input_format, buffer=data)
            for (slot, subslot, name), value in zip(reversed(input_fields), reversed(values)):
                subslot = self.slots[slot].subslots[subslot]
                if name == "IOPS":
                    subslot.input_iops = PNIORealTime_IOxS(bytes([value]))
                elif name == "IOCS":
                    subslot.output_iocs = PNIORealTime_IOxS(bytes([value]))
                elif subslot.input_iops.dataState == 1:
                    subslot.input_data[name] = value
                else:
                    subslot.input_data[name] = None
            LOGGER.debug("Input frame: %r", self.slots)
            self._signal_update()
        for frame_id in assoc.input_frame_ids:
            self.rt.register_frame_handler(frame_id, _handle_input_frame)


class ProfinetInterface:
    rt: RTProtocol
    rpc: DceRpcProtocol
    alarm_reference: int

    @classmethod
    async def from_config(cls, config: ConfigReader):
        return await create_profinet_interface(config.config["ifname"])

    def __init__(self, rt: RTProtocol, rpc: DceRpcProtocol):
        self.rt = rt
        self.rpc = rpc
        self.alarm_reference = 1

    @asynccontextmanager
    async def open_device(self, name_of_station: str, extra_blocks=[]) -> AsyncGenerator[ProfinetDevice, None]:
        alarm_reference = self.alarm_reference
        self.alarm_reference += 1

        device = ProfinetDevice(rt=self.rt, rpc=self.rpc, name_of_station=name_of_station, alarm_reference=alarm_reference)

        yield device

    @asynccontextmanager
    async def open_device_from_config(self, config: ConfigReader) -> AsyncGenerator[ProfinetDevice, None]:
        alarm_reference = self.alarm_reference
        self.alarm_reference += 1

        device = ProfinetDeviceConfig(rt=self.rt, rpc=self.rpc, config=config, alarm_reference=alarm_reference)
        async with asyncio.TaskGroup() as tg:
            for cr in config.output_crs:
                LOGGER.info("Starting cyclic data task for %s", cr.show2(dump=True))
                tg.create_task(device._cyclic_data_task(cr))
            tg.create_task(device._reconnect_task())
            await device.connected.wait()
            yield device
            tg._abort()


async def create_profinet_interface(ifname: str) -> ProfinetInterface:
    rt = await create_rt_endpoint(ifname)
    rpc = await create_rpc_endpoint()
    return ProfinetInterface(rt=rt, rpc=rpc)
