import random

from scapy.layers.l2 import Ether
from scapy.layers.dcerpc import DceRpc
from scapy.contrib.pnio_rpc import ARBlockReq
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
