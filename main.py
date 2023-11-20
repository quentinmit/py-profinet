from dataclasses import dataclass, field
import logging
import asyncio
import argparse
import json
import sys

import aiomqtt
from pint import Quantity, Unit, UnitRegistry
from scapy.config import conf
import structlog

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
            "delta_time_seconds": self.total_time.to(ureg.s).m,
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
        input_topic = self.config.mqtt_topic("inputs")
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
        for (channel_name, (slot, subslot, channel_number)) in zip(self.config.config["caparoc"]["channels"], self._actual_channels):
            if channel_name is None:
                continue
            vj = lambda tmpl: ('value_json["%d"]["%d"]["' + tmpl + '"]') % (slot, subslot, channel_number)
            status_info = vj("Channel %d status information")
            availability = avail(status_info)
            mqtt_key = "%d_%d_%d" % (slot, subslot, channel_number)
            unique_id = channel_name
            out[("switch", mqtt_key)] = {
                "availability": availability,
                "command_topic": self.config.mqtt_topic("command/%d/%d/Control channel %d" % (slot, subslot, channel_number)),
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

    async def update(self, update: Update, client: aiomqtt.Client):
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
                    await self._publish(client)
                    self.last_publish_time = now
        finally:
            self.last_cycle_count = update.input_cycle_count

    async def _publish(self, client: aiomqtt.Client):
        await client.publish(
            self.config.mqtt_topic("caparoc/inputs"),
            json.dumps(
                {
                    "total_time": self.total_cycles.seconds,
                    "total": self.total_system_energy.for_json(include_system_voltage=True),
                } | {
                    f"{slot}_{subslot}_{channel}": self.channel_total_energy[slot, subslot, channel].for_json()
                    for slot, subslot, channel in self.channel_total_energy
                }
            )
        )

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
                    if message.topic.matches("homeassistant/status") and message.payload == b"online":
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

    async def run(self):
        interface = await ProfinetInterface.from_config(self.config)

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
