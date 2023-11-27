from dataclasses import dataclass, field
import logging
import asyncio
import argparse
import json
import os
import sys
import time

from aiohttp_retry import ExponentialRetry, RetryClient
import aiomqtt
from pint import Quantity, Unit, UnitRegistry
from scapy.config import conf
import structlog
from influxdb_client import Point, WritePrecision
from influxdb_client.client.exceptions import InfluxDBError
from influxdb_client.client.influxdb_client_async import InfluxDBClientAsync

from pnio.config import ConfigReader
from pnio.controller import ProfinetDevice, ProfinetInterface, Slot, Update
from pnio.rt import CYCLE_COUNTER_HZ, CycleCounter


LOGGER = structlog.stdlib.get_logger()

ureg = UnitRegistry()
ureg.define(f"pniocycle = 1/{CYCLE_COUNTER_HZ} s")
Q_ = ureg.Quantity


def _inputs_to_json(slots: dict[int, Slot]) -> dict[int, dict[int, dict[str, int|None]]]:
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

VOLTAGE_UNIT = 10 * ureg.mV
CURRENT_UNIT = 100 * ureg.mA

@dataclass
class Accumulator:
    total: Quantity
    partial_total: Quantity
    min: Quantity|None
    max: Quantity|None

    def __init__(self, unit: Unit):
        self.total = 0 * unit * ureg.pniocycle
        self.reset()

    def reset(self):
        self.partial_total = 0 * self.total.units
        self.min = None
        self.max = None

    def add(self, value: Quantity, delta_t: Quantity):
        self.total += delta_t * value
        self.partial_total += delta_t * value
        self.min = min(value, self.min or value)
        self.max = max(value, self.max or value)

@dataclass
class EnergyAccumulator:
    # Time is in units of 1 / 32000 Hz
    total_time: Quantity = 0 * ureg.pniocycle
    # delta_time is the time since the last call to for_json
    delta_time: Quantity = 0 * ureg.pniocycle
    # Voltage-Time is in units of 10 mV / 32000 Hz
    voltage_time: Accumulator = field(default_factory=lambda: Accumulator(VOLTAGE_UNIT))
    # Energy is in units of 1 mW / 32000 Hz = 31.25 nJ
    energy: Accumulator = field(default_factory=lambda: Accumulator(VOLTAGE_UNIT * CURRENT_UNIT))
    # Charge is in units of 100 mA / 32000 Hz = 3.125 µC
    charge: Accumulator = field(default_factory=lambda: Accumulator(CURRENT_UNIT))

    def for_json(self, include_system_voltage=False) -> dict[str, float]:
        out = {
            "total_time_seconds": self.total_time.to(ureg.s).m,
            "total_energy_joules": self.energy.total.to(ureg.J).m,
            "total_charge_coulombs": self.charge.total.to(ureg.C).m,
        }
        if self.delta_time > 0:
            out |= {
                "delta_time_seconds": self.delta_time.to(ureg.s).m,
                "average_power_watts": (self.energy.partial_total / self.delta_time).to(ureg.W).m,
                "average_current_amps": (self.charge.partial_total / self.delta_time).to(ureg.A).m,
                "max_power_watts": self.energy.max.to(ureg.W).m,
                "min_power_watts": self.energy.min.to(ureg.W).m,
                "max_current_amps": self.charge.max.to(ureg.A).m,
                "min_current_amps": self.charge.min.to(ureg.A).m,
            }
        if include_system_voltage:
            out |= {
                "total_voltage_time_volt_seconds": self.voltage_time.total.to(ureg.V * ureg.s).m,
            }
            if self.delta_time > 0:
                out |= {
                    "average_voltage_volts": (self.voltage_time.partial_total / self.delta_time).to(ureg.V).m,
                    "max_voltage_volts": self.voltage_time.max.to(ureg.V).m,
                    "min_voltage_volts": self.voltage_time.min.to(ureg.V).m,
                }
        self.reset()
        return out

    def reset(self):
        self.delta_time = 0 * self.delta_time.units
        self.voltage_time.reset()
        self.energy.reset()
        self.charge.reset()

    def add(self, delta_t: Quantity, system_voltage: Quantity, current: Quantity):
        self.total_time += delta_t
        self.delta_time += delta_t
        self.voltage_time.add(system_voltage, delta_t)
        self.energy.add(system_voltage * current, delta_t)
        self.charge.add(current, delta_t)


class Caparoc:
    config: ConfigReader
    device: ProfinetDevice

    last_publish_time: float | None
    last_cycle_count: CycleCounter | None
    total_cycles: CycleCounter
    # Energy counters are in units of 10 mV * 100 mA * 31.25 µs = 1 mW / 32000 Hz
    total_system_energy: EnergyAccumulator
    channel_total_energy: dict[tuple[int, int, int], EnergyAccumulator]

    def __init__(self, config: ConfigReader, device: ProfinetDevice):
        self.config = config
        self.device = device
        self.last_publish_time = None
        self.last_cycle_count = None
        self.total_cycles = CycleCounter(0, False)
        self.total_system_energy = EnergyAccumulator()
        self.channel_total_energy = {k: EnergyAccumulator() for k in self._actual_channels}

    @property
    def _actual_channels(self) -> list[tuple[int, int, int]]:
        return sorted([
            (i, j, int(name.split()[2]))
            for i, slot in self.device.slots.items()
            for j, subslot in slot.subslots.items()
            for name in subslot.output_data
            if name.startswith("Control channel")
        ])

    def get_discovery_messages(self) -> dict[tuple[str, str], dict]:
        input_topic = self.config.mqtt_topic("caparoc/inputs")
        device_name = self.config.config["mqtt"]["device"]["name"]
        ha_device = {
            "connections": [
                ["mac", self.device.mac],
            ],
            "manufacturer": self.config.gsdml.vendor_name,
            "model": self.config.gsdml.device_info,
            "name": device_name,
        }
        out = {}
        def entity(*path, **kwargs):
            expr = 'value_json' + ''.join(f'["{v}"]' for v in path)
            return {
                "availability": [{
                    "topic": input_topic,
                    "value_template": "{%% if %s is none %%}offline{%% else %%}online{%% endif %%}" % (expr),
                }],
                "device": ha_device,
                "state_topic": input_topic,
                "value_template": "{{ %s }}" % (expr,),
            } | kwargs
        def sensor(*path, **kwargs):
            kwargs = {
                "state_class": "measurement",
            } | kwargs
            return entity(*path, **kwargs)
        out[("sensor", "total_current")] = sensor(
            "total", "average_current_amps",
            device_class="current",
            name="Total system current",
            unique_id="%s_total_current" % (device_name,),
            unit_of_measurement="A",
            suggested_display_precision=1,
        )
        out[("sensor", "input_voltage")] = sensor(
            "total", "average_voltage_volts",
            device_class="voltage",
            name="System input voltage",
            unique_id="%s_input_voltage" % (device_name,),
            unit_of_measurement="V",
            suggested_display_precision=2,
        )
        # TODO: Expose binary sensors for undervoltage, overvoltage, channel error, warning, total current shutdown
        for (channel_name, (slot, subslot, channel_number)) in zip(self.config.config["caparoc"]["channels"], self._actual_channels):
            if channel_name is None:
                continue
            mqtt_key = "%d_%d_%d" % (slot, subslot, channel_number)
            unique_id = channel_name
            out[("switch", mqtt_key)] = entity(
                mqtt_key, "status",
                command_topic=self.config.mqtt_topic("command/%d/%d/Control channel %d" % (slot, subslot, channel_number)),
                #entity_category="config",
                payload_on="129",
                payload_off="128",
                qos=1,
                name=channel_name,
                unique_id="%s_%s" % (device_name, unique_id),
                state_on="True",
                state_off="False",
            )
            out[("sensor", f"{mqtt_key}_nominal_current")] = sensor(
                mqtt_key, "nominal_current_amps",
                device_class="current",
                entity_category="diagnostic",
                name="%s nominal current" % (channel_name,),
                unique_id="%s_%s_nominal_current" % (device_name, unique_id),
                unit_of_measurement="A",
                suggested_display_precision=0,
            )
            out[("sensor", f"{mqtt_key}_load_current")] = sensor(
                mqtt_key, "average_current_amps",
                device_class="current",
                name="%s load current" % (channel_name,),
                unique_id="%s_%s_load_current" % (device_name, unique_id),
                unit_of_measurement="A",
                suggested_display_precision=1,
            )
            # TODO: Binary sensors for overload, short circuit, defect?
        return out

    async def update(self, update: Update, client: aiomqtt.Client, influxdb_queue: asyncio.Queue):
        try:
            if self.last_cycle_count and update.input_cycle_count:
                delta_t = (update.input_cycle_count - self.last_cycle_count)
                self.total_cycles += delta_t

                delta_t = delta_t.value * ureg.pniocycle
                # Units of 10 mV
                system_voltage = update.slots[0].subslots[2].input_data["System input voltage"]
                # Units of 100 mA
                system_current = update.slots[0].subslots[2].input_data["Total system current"]

                if system_voltage is not None and system_current is not None:
                    self.total_system_energy.add(delta_t, system_voltage * VOLTAGE_UNIT, system_current * CURRENT_UNIT)

                for slot, subslot, channel in self._actual_channels:
                    channel_current = update.slots[slot].subslots[subslot].input_data[f"Channel {channel} load current"]
                    if system_voltage and channel_current is not None:
                        self.channel_total_energy[slot, subslot, channel].add(delta_t, system_voltage * VOLTAGE_UNIT, channel_current * CURRENT_UNIT)

                now = asyncio.get_running_loop().time()
                if not self.last_publish_time or (now - self.last_publish_time) > self.config.config["caparoc"].get("publish_interval", 1.0):
                    await self._publish(client, influxdb_queue, update)
                    self.last_publish_time = now
        finally:
            self.last_cycle_count = update.input_cycle_count

    def _state_to_json(self, update: Update):
        _BITS = ["status", "current_over_80percent", "overload", "short_circuit", "defect"]
        def channel_status(slot, subslot, channel):
            info = update.slots[slot].subslots[subslot].input_data[f"Channel {channel} status information"]
            return {
                key: None if info is None else info & (1 << i) != 0
                for i, key in enumerate(_BITS)
            } | {
                "nominal_current_amps": update.slots[slot].subslots[subslot].input_data[f"Channel {channel} nominal current"],
            }
        return ({
            "total": self.total_system_energy.for_json(include_system_voltage=True) | {
                "total_cycles": self.total_cycles.value,
            },
        } | {
            f"{slot}_{subslot}_{channel}":
            self.channel_total_energy[slot, subslot, channel].for_json() | channel_status(slot, subslot, channel)
            for slot, subslot, channel in self.channel_total_energy
        })

    async def _publish(self, client: aiomqtt.Client, influxdb_queue: asyncio.Queue, update: Update):
        j = self._state_to_json(update)
        await client.publish(
            self.config.mqtt_topic("caparoc/inputs"),
            json.dumps(
                j
            )
        )
        now = int(time.time() * 1e9)
        points = []
        for channel, values in j.items():
            p = Point("caparoc").tag("channel", channel).tag("name_of_station", self.config.config["name_of_station"]).time(now, WritePrecision.NS)
            for k, v in values.items():
                p.field(k, v)
            points.append(p)
        if influxdb_queue.full():
            # If the queue is full, pop the oldest batch so we prefer more recent points
            influxdb_queue.get_nowait()
        influxdb_queue.put_nowait(points)

class ProfinetMqtt:
    def __init__(self, config: ConfigReader):
        self.config = config
        self.plugins = []

    def _get_discovery_messages(self) -> dict[tuple[str, str], dict]:
        out = {}
        for p in self.plugins:
            out.update(p.get_discovery_messages())
        return out

    async def _run_once(self, device: ProfinetDevice, client: aiomqtt.Client):
        output_topic = self.config.mqtt_topic("outputs")
        input_topic = self.config.mqtt_topic("inputs")
        command_topic = self.config.mqtt_topic("command/#")
        async def mqtt2pnio():
            async with client.messages() as messages:
                await client.subscribe("homeassistant/status")
                await client.subscribe(output_topic)
                await client.subscribe(input_topic)
                await client.subscribe(command_topic, qos=1)
                async for message in messages:
                    if message.topic.matches("homeassistant/status"):
                        # N.B. We're supposed to check for message.payload == b"online",
                        # but there appears to be a race and sometimes the payload is b"offline"
                        # even if HA is running.
                        LOGGER.info("received Home Assistant birth message; sending discovery messages")
                        # Home Assistant is (newly?) online, send discovery messages
                        for (domain, name), payload in self._get_discovery_messages().items():
                            await client.publish(
                                "homeassistant/%s/%s/%s/config" % (
                                    domain,
                                    self.config.config["name_of_station"],
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
            last_publish_time = asyncio.get_running_loop().time()
            async for update in device.updates:
                async with asyncio.TaskGroup() as tg:
                    now = asyncio.get_running_loop().time()
                    if now - last_publish_time > 1.0 or update.input_cycle_count is None:
                        tg.create_task(client.publish("workshop/power/inputs", payload=json.dumps(_inputs_to_json(update.slots))))
                        tg.create_task(client.publish("workshop/power/outputs", payload=json.dumps(_outputs_to_json(device.slots)), retain=True))
                        last_publish_time = now
                    for p in self.plugins:
                        tg.create_task(p.update(update, client))
        async with asyncio.TaskGroup() as tg:
            tg.create_task(mqtt2pnio())
            tg.create_task(pnio2mqtt())

    async def _run_influxdb(self, queue: asyncio.Queue):
        try:
            host = os.environ["INFLUX_HOST"]
            token = os.environ["INFLUX_TOKEN"]
            org = os.environ["INFLUX_ORG"]
            bucket = os.environ["INFLUX_BUCKET"]
        except KeyError:
            LOGGER.warning("not writing to influxdb; environment variable missing", exc_info=True)
            while True:
                await queue.get()
                queue.task_done()
        async with InfluxDBClientAsync(
                url=host, token=token, org=org,
                client_session_type=RetryClient,
                client_session_kwargs={"retry_options": ExponentialRetry(attempts=3)},
        ) as client:
            write_api = client.write_api()
            while True:
                batch = await queue.get()
                try:
                    await write_api.write(bucket=bucket, record=batch)
                except InfluxDBError:
                    LOGGER.exception("failed writing point")
                finally:
                    queue.task_done()
    async def run(self):
        interface = await ProfinetInterface.from_config(self.config)

        influxdb_queue = asyncio.Queue()
        async with asyncio.TaskGroup() as tg:
            tg.create_task(self._run_influxdb(influxdb_queue))

            async with interface.open_device_from_config(self.config) as device:
                self.plugins = []
                if "caparoc" in self.config.config:
                    self.plugins.append(Caparoc(self.config, device))
                while True:
                    try:
                        async with aiomqtt.Client(self.config.mqtt_server) as mqtt_client:
                            await self._run_once(device, mqtt_client)
                    except aiomqtt.MqttError:
                        LOGGER.exception("mqtt connection lost; reconnecting")
                        await asyncio.sleep(1)

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

    await ProfinetMqtt(config).run()

if __name__ == "__main__":
    setup_logging()
    asyncio.run(main())
