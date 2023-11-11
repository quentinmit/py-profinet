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
            async for slots in device.updates:
                data = _to_json(slots)
                await mqtt_client.publish("workshop/power/status", payload=json.dumps(data))

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
