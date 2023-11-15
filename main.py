import logging
import asyncio
import argparse
import json

from scapy.config import conf
import asyncio_mqtt as aiomqtt

from pnio.config import ConfigReader
from pnio.controller import ProfinetDevice, ProfinetInterface, Slot

def _to_json(slots: dict[int, Slot]) -> any:
    return {
        i: {
            j: {
                k: v for k,v in subslot.input_data.items()
            } | {
                "IOPS": bytes(subslot.input_iops)[0],
            }
            for j, subslot in slot.subslots.items()
        } for i, slot in slots.items()
    }

def _outputs_to_json(slots: dict[int, Slot]) -> any:
    return {
        i: {
            j: {
                k: v for k,v in subslot.output_data.items()
            }
            for j, subslot in slot.subslots.items()
        } for i, slot in slots.items()
    }

def get_discovery_messages(config: ConfigReader, device: ProfinetDevice) -> dict[tuple[str, str], dict]:
    input_topic = config.mqtt_topic("inputs")
    output_topic = config.mqtt_topic("outputs")
    device_name = config.config["mqtt"]["device"]["name"]
    device = {
        "connections": [
            ["mac", device.mac],
        ],
        "manufacturer": config.gsdml.vendor_name,
        "model": config.gsdml.device_info,
        "name": device_name,
    }
    out = {}
    if caparoc := config.config.get("caparoc"):
        avail = lambda vj_expr: ([
            "topic": input_topic,
            "value_template": "{%% if %s is None %%}offline{%% else %%}online{%% endif %%}" % (vj_expr),
        ])
        total_current = 'value_json["0"]["2"]["Total system current"]'
        out[("sensor", "total_current")] = {
            "availability": avail(total_current),
            "device": device,
            "device_class": "current",
            "state_class": "measurement",
            "name": "Total system current",
            "state_topic": input_topic,
            "value_template": "{{ %s * 0.1 }}" % (total_current,),
            "unit_of_measurement": "A",
        }
        input_voltage = 'value_json["0"]["2"]["System input voltage"]'
        out[("sensor", "input_voltage")] = {
            "availability": avail(input_voltage),
            "device": device,
            "device_class": "voltage",
            "state_class": "measurement",
            "name": "System input voltage",
            "state_topic": input_topic,
            "value_template": "{{ %s * 0.01 }}" % (input_voltage,),
            "unit_of_measurement": "V",
        }
        # TODO: Expose binary sensors for undervoltage, overvoltage, channel error, warning, total current shutdown
        actual_channels = sorted([
            (i, j, int(name.split()[3]))
            for i, slot in device.slots.items()
            for j, subslot in slot.subslots.items()
            for name in subslot.output_data
            if name.startswith("Control channel")
        ])
        for (channel_name, (slot, subslot, channel_number)) in zip(caparoc["channels"], actual_channels):
            vj = lambda tmpl: ('value_json["%d"]["%d"]["' + tmpl + '"]') % (slot, subslot, channel_number)
            status_info = vj("Channel %d status information")
            availability = avail(status_info)
            unique_id = "%d_%d_%d" % (slot, subslot, channel_number)
            out[("switch", unique_id)] = {
                "availability": availability,
                "command_topic": output_topic,
                "device": device,
                #"entity_category": "config",
                "payload_on": """{"%d": {"%d": {"Control channel %d": 129}}}""" % (slot, subslot, channel_number),
                "payload_off": """{"%d": {"%d": {"Control channel %d": 128}}}""" % (slot, subslot, channel_number),
                "qos": 1,
                "retain": True,
                "name": channel_name,
                "unique_id": "%s_%s" % (device_name, unique_id),
                "state_topic": input_topic,
                "state_on": "True",
                "state_off": "False",
                "value_template": "{{ %s & 1 != 0 }}" % (status_info,)
            }
            out[("sensor", "%s_nominal_current" % (unique_id,))] = {
                "availability": availability,
                "device": device,
                "device_class": "current",
                "entity_category": "diagnostic",
                "name": "%s nominal current" % (channel_name,),
                "state_topic": input_topic,
                "value_template": "{{ %s }}" % (vj("Channel %s nominal current"),),
                "unit_of_measurement": "A",
            }
            out[("sensor", "%s_load_current" % (unique_id,))] = {
                "availability": availability,
                "device": device,
                "device_class": "current",
                "state_class": "measurement",
                "name": "%s load current" % (channel_name,),
                "state_topic": input_topic,
                "value_template": "{{ %s * 0.1 }}" % (vj("Channel %s load current"),),
                "unit_of_measurement": "A",
            }
            # TODO: Binary sensors for overload, short circuit, defect?
    return out

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('filename')
    parser.add_argument('-v', '--verbose', action='count', default=0)
    args = parser.parse_args()

    if args.verbose > 1:
        conf.debug_match = args.verbose
        logging.getLogger().setLevel(logging.DEBUG)
    if args.verbose > 2:
        logging.getLogger().setLevel(logging.DEBUG)

    config = ConfigReader(args.filename)

    interface = await ProfinetInterface.from_config(config)

    async with interface.open_device_from_config(config) as device:
        async with aiomqtt.Client(config.config["mqtt_server"]) as mqtt_client:
            async def mqtt2pnio():
                async with mqtt_client.messages() as messages:
                    await mqtt_client.subscribe("homeassistant/status")
                    await mqtt_client.subscribe("workshop/power/outputs", qos=1)
                    await mqtt_client.subscribe("workshop/power/inputs")
                    outputs_seen = False
                    async for message in messages:
                        if message.topic.matches("homeassistant/status") and message.payload == "online":
                            # Home Assistant is (newly?) online, send discovery messages
                            for (domain, name), payload in get_discovery_messages(config, device):
                                await mqtt_client.publish(
                                    "homeassistant/%s/%s/%s/config" % (
                                        domain,
                                        config.config["name_of_station"],
                                        name,
                                    ),
                                    payload=json.dumps(payload),
                                )
                        if message.topic.matches("workshop/power/outputs"):
                            outputs_seen = True
                            data = json.loads(message.payload)
                            for slot, subslots in data.items():
                                for subslot, fields in subslots.items():
                                    for k, v in fields.items():
                                        device.slots[int(slot)].subslots[int(subslot)].output_data[k] = v
                        if not message.retain:
                            if not outputs_seen:
                                await mqtt_client.publish("workshop/power/outputs", payload=json.dumps(_outputs_to_json(device.slots)), retain=True, qos=1)
                                outputs_seen = True
            async def pnio2mqtt():
                async for slots in device.updates:
                    data = _to_json(slots)
                    await mqtt_client.publish("workshop/power/inputs", payload=json.dumps(data))
            async with asyncio.TaskGroup() as tg:
                tg.create_task(mqtt2pnio())
                tg.create_task(pnio2mqtt())

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
