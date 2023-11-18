import logging
import asyncio
import argparse
import json
import sys

import aiomqtt
from scapy.config import conf
import structlog

from pnio.config import ConfigReader
from pnio.controller import ProfinetDevice, ProfinetInterface, Slot

def _to_json(slots: dict[int, Slot]) -> dict[int, dict[int, dict[str, int|bytes]]]:
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

def _outputs_to_json(slots: dict[int, Slot]) -> dict:
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
    device_name = config.config["mqtt"]["device"]["name"]
    ha_device = {
        "connections": [
            ["mac", device.mac],
        ],
        "manufacturer": config.gsdml.vendor_name,
        "model": config.gsdml.device_info,
        "name": device_name,
    }
    out = {}
    if caparoc := config.config.get("caparoc"):
        avail = (lambda vj_expr: [{
            "topic": input_topic,
            "value_template": "{%% if %s is none %%}offline{%% else %%}online{%% endif %%}" % (vj_expr),
        }])
        total_current = 'value_json["0"]["2"]["Total system current"]'
        out[("sensor", "total_current")] = {
            "availability": avail(total_current),
            "device": ha_device,
            "device_class": "current",
            "state_class": "measurement",
            "name": "Total system current",
            "unique_id": "%s_total_current" % (device_name,),
            "state_topic": input_topic,
            "value_template": "{{ %s * 0.1 }}" % (total_current,),
            "unit_of_measurement": "A",
            "suggested_display_precision": 1,
        }
        input_voltage = 'value_json["0"]["2"]["System input voltage"]'
        out[("sensor", "input_voltage")] = {
            "availability": avail(input_voltage),
            "device": ha_device,
            "device_class": "voltage",
            "state_class": "measurement",
            "name": "System input voltage",
            "unique_id": "%s_input_voltage" % (device_name,),
            "state_topic": input_topic,
            "value_template": "{{ %s * 0.01 }}" % (input_voltage,),
            "unit_of_measurement": "V",
            "suggested_display_precision": 2,
        }
        # TODO: Expose binary sensors for undervoltage, overvoltage, channel error, warning, total current shutdown
        actual_channels = sorted([
            (i, j, int(name.split()[2]))
            for i, slot in device.slots.items()
            for j, subslot in slot.subslots.items()
            for name in subslot.output_data
            if name.startswith("Control channel")
        ])
        for (channel_name, (slot, subslot, channel_number)) in zip(caparoc["channels"], actual_channels):
            if channel_name is None:
                continue
            vj = lambda tmpl: ('value_json["%d"]["%d"]["' + tmpl + '"]') % (slot, subslot, channel_number)
            status_info = vj("Channel %d status information")
            availability = avail(status_info)
            mqtt_key = "%d_%d_%d" % (slot, subslot, channel_number)
            unique_id = channel_name
            out[("switch", mqtt_key)] = {
                "availability": availability,
                "command_topic": config.mqtt_topic("command/%d/%d/Control channel %d" % (slot, subslot, channel_number)),
                "device": ha_device,
                #"entity_category": "config",
                "payload_on": "129",
                "payload_off": "128",
                "qos": 1,
                "name": channel_name,
                "unique_id": "%s_%s" % (device_name, unique_id),
                "state_topic": input_topic,
                "state_on": "True",
                "state_off": "False",
                "value_template": "{{ %s %% 2 != 0 }}" % (status_info,)
            }
            out[("sensor", f"{mqtt_key}_nominal_current")] = {
                "availability": availability,
                "device": ha_device,
                "device_class": "current",
                "entity_category": "diagnostic",
                "name": "%s nominal current" % (channel_name,),
                "unique_id": "%s_%s_nominal_current" % (device_name, unique_id),
                "state_topic": input_topic,
                "value_template": "{{ %s }}" % (vj("Channel %s nominal current"),),
                "unit_of_measurement": "A",
                "suggested_display_precision": 0,
            }
            out[("sensor", f"{mqtt_key}_load_current")] = {
                "availability": availability,
                "device": ha_device,
                "device_class": "current",
                "state_class": "measurement",
                "name": "%s load current" % (channel_name,),
                "unique_id": "%s_%s_load_current" % (device_name, unique_id),
                "state_topic": input_topic,
                "value_template": "{{ %s * 0.1 }}" % (vj("Channel %s load current"),),
                "unit_of_measurement": "A",
                "suggested_display_precision": 1,
            }
            # TODO: Binary sensors for overload, short circuit, defect?
    return out

def setup_logging():
    console = sys.stderr.isatty()

    shared_processors = [
        #structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.CallsiteParameterAdder(
            {
                structlog.processors.CallsiteParameter.FILENAME,
                structlog.processors.CallsiteParameter.FUNC_NAME,
                structlog.processors.CallsiteParameter.LINENO,
            }
        ),
    ]

    formatter_processors = []

    if console:
        shared_processors.extend([
            structlog.processors.format_exc_info,
        ])
        formatter_processors.extend([
            # Remove _record & _from_structlog.
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.dev.ConsoleRenderer(),
        ])
    else:
        formatter_processors.extend([
            structlog.PrintLogger(file=sys.stderr)
        ])

    structlog.configure(
        processors=shared_processors + [
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        # These run ONLY on `logging` entries that do NOT originate within
        # structlog.
        foreign_pre_chain=shared_processors,
        # These run on ALL entries after the pre_chain is done.
        processors=formatter_processors,
    )

    handler = logging.StreamHandler()
    # Use OUR `ProcessorFormatter` to format all `logging` entries.
    handler.setFormatter(formatter)
    root_logger = logging.getLogger()
    root_logger.addHandler(handler)
    root_logger.setLevel(logging.INFO)

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('filename')
    parser.add_argument('-v', '--verbose', action='count', default=0)
    args = parser.parse_args()

    if args.verbose > 1:
        conf.debug_match = args.verbose
        logging.getLogger().setLevel(logging.DEBUG)
    if args.verbose > 0:
        logging.getLogger().setLevel(logging.DEBUG)

    config = ConfigReader(args.filename)

    interface = await ProfinetInterface.from_config(config)

    async with interface.open_device_from_config(config) as device:
        async with aiomqtt.Client(config.mqtt_server) as mqtt_client:
            output_topic = config.mqtt_topic("outputs")
            input_topic = config.mqtt_topic("inputs")
            command_topic = config.mqtt_topic("command/#")
            async def mqtt2pnio():
                async with mqtt_client.messages() as messages:
                    await mqtt_client.subscribe("homeassistant/status")
                    await mqtt_client.subscribe(output_topic)
                    await mqtt_client.subscribe(input_topic)
                    await mqtt_client.subscribe(command_topic, qos=1)
                    async for message in messages:
                        if message.topic.matches("homeassistant/status") and message.payload == b"online":
                            logging.info("Received Home Assistant birth message; sending discovery messages")
                            # Home Assistant is (newly?) online, send discovery messages
                            for (domain, name), payload in get_discovery_messages(config, device).items():
                                await mqtt_client.publish(
                                    "homeassistant/%s/%s/%s/config" % (
                                        domain,
                                        config.config["name_of_station"],
                                        name,
                                    ),
                                    payload=json.dumps(payload),
                                )
                        if message.topic.matches(output_topic) and message.retain:
                            # Reload initial output state from MQTT
                            data = json.loads(message.payload)
                            for slot, subslots in data.items():
                                for subslot, fields in subslots.items():
                                    for k, v in fields.items():
                                        device.slots[int(slot)].subslots[int(subslot)].output_data[k] = v
                        if message.topic.matches(command_topic):
                            slot, subslot, field = message.topic.value.split("/")[-3:]
                            device.slots[int(slot)].subslots[int(subslot)].output_data[field] = json.loads(message.payload)
            async def pnio2mqtt():
                async for slots in device.updates:
                    data = _to_json(slots)
                    await mqtt_client.publish("workshop/power/inputs", payload=json.dumps(data))
                    await mqtt_client.publish("workshop/power/outputs", payload=json.dumps(_outputs_to_json(device.slots)), retain=True)
            async with asyncio.TaskGroup() as tg:
                tg.create_task(mqtt2pnio())
                tg.create_task(pnio2mqtt())

if __name__ == "__main__":
    setup_logging()
    asyncio.run(main())
