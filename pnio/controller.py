from contextlib import asynccontextmanager
import asyncio
import logging
from collections.abc import AsyncGenerator

from .config import ConfigReader
from .rpc import Association, ContextManagerActivity, DceRpcProtocol, create_rpc_endpoint
from .rt import RTProtocol, create_rt_endpoint
from .pnio_dcp import DeviceInstanceBlock, IPParameterBlock, DeviceIDBlock
from .pnio_rpc import IOCRBlockReq

from scapy.layers.l2 import Ether


LOGGER = logging.getLogger("profinet.controller")


def cycle_count() -> int:
    return int(asyncio.get_running_loop().time() * 32000)


class ProfinetDevice:
    rt: RTProtocol
    assoc: Association
    mac: str | bytes

    def __init__(self, rt: RTProtocol, assoc: Association, mac: str | bytes):
        self.rt = rt
        self.assoc = assoc
        self.mac = mac

    async def _cyclic_data_task(self, cr: IOCRBlockReq):
        cycle_interval = cr.SendClockFactor * cr.ReductionRatio
        LOGGER.debug("Starting cyclic data for output frame 0x%04x every 0x%04x cycles", cr.FrameID, cycle_interval)
        while True:
            now = cycle_count()
            next_cycle_count = ((now // cycle_interval + 1) * cr.ReductionRatio + cr.Phase) * cr.SendClockFactor
            LOGGER.debug("Current cycle counter %d, next cycle counter %d", now, next_cycle_count)
            await asyncio.sleep((next_cycle_count - now) / 32000)
            data = bytearray(40) # TODO
            await self.rt.send_cyclic_data_frame(
                data=data,
                frame_id=cr.FrameID,
                dst_mac=self.mac,
                cycle_counter=next_cycle_count,
            )


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
                for block in connect_blocks:
                    if isinstance(block, IOCRBlockReq) and block.IOCRType == 2: # output
                        LOGGER.info("Starting cyclic data task for %s", block.show2(dump=True))
                        tg.create_task(device._cyclic_data_task(block))
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
