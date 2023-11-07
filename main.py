import logging
import asyncio
import argparse

from scapy.config import conf

from pnio.config import ConfigReader
from pnio.controller import ProfinetInterface

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
        i = 0
        while True:
            j = 0
            for index, slot in device.slots.items():
                if index == 0:
                    continue
                for subslot in slot.subslots.values():
                    for k in subslot.output_data:
                        subslot.output_data[k] = 0x80 | (1 if (i & (1 << j)) else 0)
                        j += 1
            await asyncio.sleep(1)
            i += 1
        await asyncio.get_running_loop().create_future()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
