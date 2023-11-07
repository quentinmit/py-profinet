from contextlib import asynccontextmanager
import asyncio
from dataclasses import dataclass, field
import logging
from collections.abc import AsyncGenerator
import struct

from .pnio import PNIORealTime_IOxS, PNIORealTimeCyclicDefaultRawData, ProfinetIO

from .config import ConfigReader
from .rpc import Association, ContextManagerActivity, DceRpcProtocol, create_rpc_endpoint
from .rt import RTProtocol, create_rt_endpoint
from .pnio_dcp import DeviceInstanceBlock, IPParameterBlock, DeviceIDBlock
from .pnio_rpc import IOCRBlockReq

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
    assoc: Association
    mac: str | bytes
    slots: dict[int, Slot]

    def __init__(self, rt: RTProtocol, assoc: Association, mac: str | bytes):
        self.rt = rt
        self.assoc = assoc
        self.mac = mac
        self.slots = {}

    async def _cyclic_data_task(self, config: ConfigReader, cr: IOCRBlockReq):
        cycle_interval = cr.SendClockFactor * cr.ReductionRatio
        LOGGER.debug("Starting cyclic data for output frame 0x%04x every 0x%04x cycles", cr.FrameID, cycle_interval)
        while True:
            now = cycle_count()
            next_cycle_count = ((now // cycle_interval + 1) * cr.ReductionRatio + cr.Phase) * cr.SendClockFactor
            LOGGER.debug("Current cycle counter %d, next cycle counter %d", now, next_cycle_count)
            await asyncio.sleep((next_cycle_count - now) / 32000)
            data = bytearray(config.output_frame_size)
            for slot in config.slots:
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
            await self.rt.send_cyclic_data_frame(
                data=data,
                frame_id=cr.FrameID,
                dst_mac=self.mac,
                cycle_counter=next_cycle_count,
            )

    def _register_frames(self, config: ConfigReader):
        input_format, input_fields = config.input_struct
        for slot in config.slots:
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
                elif subslot.input_iops.dataState == 1: # IOPS
                    subslot.input_data[name] = value
            LOGGER.info("Input frame: %r", self.slots)
        self.rt.register_frame_handler(0x8001, _handle_input_frame) # TODO: Get frame ID from somewhere


class ProfinetInterface:
    rt: RTProtocol
    rpc: DceRpcProtocol

    @classmethod
    async def from_config(cls, config: ConfigReader):
        return await create_profinet_interface(config.config["ifname"])

    def __init__(self, rt: RTProtocol, rpc: DceRpcProtocol):
        self.rt = rt
        self.rpc = rpc

    @asynccontextmanager
    async def open_device(self, name_of_station: str, extra_blocks=[]) -> AsyncGenerator[ProfinetDevice, None]:
        pkt = await self.rt.dcp_identify(name_of_station)
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
        async with cmrpc.connect(
                cm_mac_addr=self.rt.src_mac,
                extra_blocks=extra_blocks,
        ) as assoc:
            yield ProfinetDevice(mac=mac, rt=self.rt, assoc=assoc)

    @asynccontextmanager
    async def open_device_from_config(self, config: ConfigReader) -> AsyncGenerator[ProfinetDevice, None]:
        connect_blocks = config.connect_blocks
        async with asyncio.TaskGroup() as tg:
            async with self.open_device(
                    name_of_station=config.config["name_of_station"],
                    extra_blocks=connect_blocks,
            ) as device:
                device._register_frames(config)
                for block in connect_blocks:
                    if isinstance(block, IOCRBlockReq) and block.IOCRType == 2: # output
                        LOGGER.info("Starting cyclic data task for %s", block.show2(dump=True))
                        tg.create_task(device._cyclic_data_task(config, block))
                # TODO: Use IODWriteMultipleReq?
                for slot, subslot, index, value in config.parameter_values:
                    await device.assoc.write(data=value, slot=slot, subslot=subslot, index=index)
                await device.assoc.parameter_end()
                # TODO: Await ApplicationReady
                yield device
                tg._abort()


async def create_profinet_interface(ifname: str) -> ProfinetInterface:
    rt = await create_rt_endpoint(ifname)
    rpc = await create_rpc_endpoint()
    return ProfinetInterface(rt=rt, rpc=rpc)
