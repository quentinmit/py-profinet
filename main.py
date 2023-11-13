import logging
import asyncio
import argparse
import json

from scapy.config import conf
import asyncio_mqtt as aiomqtt

from pnio.config import ConfigReader
from pnio.controller import ProfinetInterface, Slot

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
                    await mqtt_client.subscribe("workshop/power/outputs", qos=1)
                    await mqtt_client.subscribe("workshop/power/inputs")
                    outputs_seen = False
                    async for message in messages:
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
