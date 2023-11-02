from scapy.all import *
from scapy.contrib.dce_rpc import *
from scapy.contrib.pnio_rpc import *
from scapy.contrib.dce_rpc import *

load_contrib("dce_rpc")
load_contrib("pnio_rpc")

def get_application_ready_res_msg(ip, auuid, obj_uuid, interface_uuid, activity_uuid):
    ip_msg = IP(dst=ip)
    udp_msg = UDP(
        sport=49152,
        dport=49153,
    )
    dcerpc = DceRpc(
        type="response",
        flags1=0x0A,
        flags2=0x0,
        opnum=4,
        endianness="little",
        encoding="ASCII",
        float="IEEE",
        object_uuid=obj_uuid,
        interface_uuid=interface_uuid,
        activity=activity_uuid,
    )

    pnio_iod_control_res = IODControlRes(
        block_type=0x8112, SessionKey=2, ControlCommand_Done=0x0001, ARUUID=auuid
    )

    pnio_serv_pdu = PNIOServiceResPDU(blocks=[pnio_iod_control_res])

    pnio_serv_pdu.max_count = 1340
    
    return ip_msg / udp_msg / dcerpc / pnio_serv_pdu


def get_parameter_end_msg(ip, auuid):
    ip_msg = IP(dst=ip)
    udp_msg = UDP(
        sport=49153,
        dport=34964,
    )
    dcerpc = DceRpc(
        type="request",
        flags1=0x28,
        flags2=0x0,
        opnum=4,
        endianness="little",
        encoding="ASCII",
        float="IEEE",
        interface_uuid="dea00001-6c97-11d1-8271-00a02442df7d",
        activity="df16c5b3-2794-11b2-8000-a381734cba00",
    )

    pnio_iod_control_req = IODControlReq(ControlCommand_PrmEnd=0x0001, ARUUID=auuid)

    pnio_serv_pdu = PNIOServiceReqPDU(args_max=16696, blocks=[pnio_iod_control_req])

    return ip_msg / udp_msg / dcerpc / pnio_serv_pdu


def get_ping_msg(ip):
    ip_msg = IP(dst=ip)
    udp_msg = UDP(
        sport=49153,
        dport=34964,
    )
    dcerpc = DceRpc(
        type="request",
        flags1=0x28,
        flags2=0x0,
        opnum=0,
        endianness="little",
        encoding="ASCII",
        float="IEEE",
        interface_uuid="dea00001-6c97-11d1-8271-00a02442df7d",
        activity="df16c5b3-2794-11b2-8000-a381734cba00",
    )

    return ip_msg / udp_msg / dcerpc


def main():
    get_ping_msg("192.168.178.155")


if __name__ == "__main__":
    main()
