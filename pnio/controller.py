from .config import ConfigReader
from .rpc import ContextManagerActivity, DceRpcProtocol, create_rpc_endpoint
from .rt import RTProtocol, create_rt_endpoint
from .pnio_dcp import DeviceInstanceBlock, IPParameterBlock, DeviceIDBlock

from scapy.layers.l2 import Ether


class ProfinetDevice:
    rt: RTProtocol
    cmrpc: ContextManagerActivity

    def __init__(self, rt: RTProtocol, cmrpc: ContextManagerActivity):
        self.rt = rt
        self.cmrpc = cmrpc


class ProfinetInterface:
    rt: RTProtocol
    rpc: DceRpcProtocol

    @classmethod
    async def from_config(cls, config: ConfigReader) -> ProfinetInterface:
        return await create_profinet_interface(config.config["ifname"])

    def __init__(self, rt: RTProtocol, rpc: DceRpcProtocol):
        self.rt = rt
        self.rpc = rpc

    async def open_device(self, name_of_station: str) -> ProfinetDevice:
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
        return ProfinetDevice(rt=self.rt, cmrpc=cmrpc)

    async def open_device_from_config(self, config: ConfigReader) -> ProfinetDevice:
        return await self.open_device(config.config["name_of_station"])


async def create_profinet_interface(ifname: str) -> ProfinetInterface:
    rt = await create_rt_endpoint(ifname)
    rpc = await create_rpc_endpoint()
    return ProfinetInterface(rt=rt, rpc=rpc)
