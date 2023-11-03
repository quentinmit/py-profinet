from contextlib import asynccontextmanager
import logging
from collections.abc import AsyncGenerator

from .config import ConfigReader
from .rpc import Association, ContextManagerActivity, DceRpcProtocol, create_rpc_endpoint
from .rt import RTProtocol, create_rt_endpoint
from .pnio_dcp import DeviceInstanceBlock, IPParameterBlock, DeviceIDBlock

from scapy.layers.l2 import Ether


LOGGER = logging.getLogger("profinet.controller")


class ProfinetDevice:
    rt: RTProtocol
    assoc: Association

    def __init__(self, rt: RTProtocol, assoc: Association):
        self.rt = rt
        self.assoc = assoc


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
            yield ProfinetDevice(rt=self.rt, assoc=assoc)

    @asynccontextmanager
    async def open_device_from_config(self, config: ConfigReader) -> AsyncGenerator[ProfinetDevice, None]:
        async with self.open_device(
                name_of_station=config.config["name_of_station"],
                extra_blocks=config.connect_blocks,
        ) as device:
            # TODO: Use IODWriteMultipleReq?
            for slot, subslot, index, value in config.parameter_values:
                await device.assoc.write(data=value, slot=slot, subslot=subslot, index=index)
            await device.assoc.parameter_end()
            # TODO: Await ApplicationReady
            yield device


async def create_profinet_interface(ifname: str) -> ProfinetInterface:
    rt = await create_rt_endpoint(ifname)
    rpc = await create_rpc_endpoint()
    return ProfinetInterface(rt=rt, rpc=rpc)
