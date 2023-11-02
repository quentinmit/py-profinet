from messages.sim_pnio_dcp import *
from messages.sim_pnio_ps import *
from messages.sim_pnio_cm import *
from getmac import get_mac_address
import uuid
import time
from scapy.all import *
from scapy.contrib.pnio_rpc import *
from scapy.contrib.dce_rpc import *
from scapy.contrib.pnio import *
import threading

load_contrib("pnio")
load_contrib("pnio_rpc")
load_contrib("dce_rpc")


class PNIOConnection:
    def __init__(self, device_name, device_ip, iface, path_to_gsdml):
        self.auuid = str(uuid.uuid4())
        self.mac_address_device = ""
        self.device_name = device_name
        self.mac_src = get_mac_address()
        self.device_ip = device_ip
        self.iface = iface
        self.device = XMLDevice(path_to_gsdml)
        self.input_data = ""
        self.message_data = PNIOPSMessage()
        self.output_data = []

    def sniff_for_answers(self):
        def update_load(pkt):
            if pkt.haslayer("PROFINET IO Real Time Cyclic Default Raw Data"):
                self.message_data = parse_data_message(pkt, self.device)

        sniff(
            lfilter=lambda d: d.src == self.mac_address_device,
            store=0,
            count=-1,
            prn=update_load,
            iface=self.iface,
        )

    # SEND CYLIC MESSAGES
    def send_messages(self):
        counter = 0
        while True:
            ps_msg = get_data_msg(
                src=self.mac_src,
                dst=self.mac_address_device,
                counter=counter,
                device=self.device,
                data=self.output_data
            )
            ans, _ = srp(ps_msg, iface="Ethernet", verbose=False)
            counter += 1
            time.sleep(1)

    def build_connection(self):
        # BEGIN CYCLIC MESSAGES
        threading.Thread(target=self.send_messages).start()
        threading.Thread(target=self.sniff_for_answers).start()

        # WRITE PARAMETERS OF DEVICE

        # ANNOUNCE PARAMETER END
        param_end_msg = get_parameter_end_msg(ip=self.device_ip, auuid=self.auuid)
        sr1(param_end_msg, iface=self.iface, verbose=False)
        # END ANNOUNCE PARAMETER END

        # WAIT FOR APPLICATION READY RESPONSE
        def send_application_ready_rsp_callback(pkt):
            app_rdy_rsp = DceRpc(pkt[Raw].load)
            if app_rdy_rsp.haslayer("IODControlReq"):
                if (
                    app_rdy_rsp.getlayer(
                        "IODControlReq"
                    ).ControlCommand_ApplicationReady
                    == 1
                ):
                    rpc_payload = app_rdy_rsp["DCE/RPC"]
                    obj_uuid = rpc_payload.object_uuid
                    interface_uuid = rpc_payload.interface_uuid
                    activity_uuid = rpc_payload.activity
                    application_ready_res_msg = get_application_ready_res_msg(
                        ip=self.device_ip,
                        auuid=self.auuid,
                        obj_uuid=obj_uuid,
                        interface_uuid=interface_uuid,
                        activity_uuid=activity_uuid,
                    )
                    send(application_ready_res_msg, iface=self.iface, verbose=False)

        sniff(
            filter=f"udp and host {self.device_ip} and port 34964",
            store=0,
            count=1,
            prn=send_application_ready_rsp_callback,
            iface=self.iface,
        )

        print("Application ready!!!")

    # END WAIT FOR APPLICATION READY RESPONSE

    # END SEND CYLIC MESSAGES


def main():
    con = PNIOConnection()
    con.build_connection()


if __name__ == "__main__":
    main()
