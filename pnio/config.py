import itertools
from dataclasses import dataclass
import os.path
import struct
import yaml

from .gsdml import GSDML, Module, Submodule
from .pnio_rpc import ExpectedSubmodule, ExpectedSubmoduleAPI, ExpectedSubmoduleBlockReq, ExpectedSubmoduleDataDescription, IOCRAPIObject, IOCRAPI, IOCRBlockReq

@dataclass
class Subslot:
    slot: int
    subslot: int
    id: int
    submodule: Submodule
    parameters: dict[int, bytes]
    input_data_offset: int | None = None
    output_data_offset: int | None = None
    # IO Provider State indicates the producer is sending valid data
    input_iops_offset: int | None = None
    output_iops_offset: int | None = None
    # IO Consumer State indicates the consumer is happy with the data
    input_iocs_offset: int | None = None
    output_iocs_offset: int | None = None

    @property
    def output_fields(self) -> tuple[str, list[str]]:
        format = ">"
        output_fields = []
        for data_item in self.submodule.output_data:
            format += data_item.data_type.format
            output_fields.append(data_item.name)
        return format, output_fields

@dataclass
class Slot:
    slot: int
    id: int
    module: Module
    subslots: list[Subslot]

class ConfigReader:
    def __init__(self, path: str):
        self.config = yaml.safe_load(open(path))
        self.gsdml = GSDML(os.path.join(os.path.dirname(path), self.config["gsdml"]))
        self._calculate_slots()

    def _parse_parameters(self, submodule: Submodule, parameters: dict[str, str|int|bool]) -> dict[int, bytes]:
        out = {}
        parameter_by_field_name = {pf.name: p for p in submodule.parameters for pf in p.fields}
        for parameter, fields in itertools.groupby(
                parameters.items(),
                key=lambda i: parameter_by_field_name.get(i[0]),
        ):
            if not parameter:
                raise ValueError(f'Unknown parameter field "{next(fields)[0]}". Supported parameter fields are {", ".join(parameter_by_field_name.keys())}.')
            fields = dict(fields)
            parameter_bytes = bytearray(parameter.length)
            for field in parameter.fields:
                value = fields.get(field.name, field.default_value)
                if isinstance(value, bool):
                    value = int(value)
                if isinstance(value, str):
                    if not field.enum:
                        raise ValueError(f'Parameter "{field.name}" does not support string values')
                    if value not in field.enum:
                        raise ValueError(f'Unsupported value "{value}" for parameter field "{field.name}". Supported values are {", ".join(field.enum.keys())}')
                    value = field.enum[value]
                match field.offset:
                    case (i, j):
                        parameter_bytes[i] |= value << j
                    case offset:
                        struct.pack_into(">" + field.data_type.format, parameter_bytes, offset, value)
            out[parameter.index] = parameter_bytes
        return out

    def _calculate_slots(self):
        out = []
        input_frame_offset = output_frame_offset = 0
        def input(n = 1):
            nonlocal input_frame_offset
            out = input_frame_offset
            input_frame_offset += n
            return out
        def output(n = 1):
            nonlocal output_frame_offset
            out = output_frame_offset
            output_frame_offset += n
            return out
        for slot, module in sorted(self.config["slots"].items()):
            g_module = self.gsdml.get_module(module["id"])
            if not g_module:
                raise ValueError("Couldn't find module 0x%04x" % (module["id"]))
            s = Slot(
                slot=slot,
                id=module["id"],
                module=g_module,
                subslots = [],
            )
            for subslot, submodule in sorted(module.get("subslots", {
                    1: {
                        "id": g_module.submodules[0].id,
                        "parameters": module.get("parameters", {}),
                    },
            }).items()):
                g_submodule = g_module.get_submodule(submodule["id"])
                if not g_submodule:
                    raise ValueError("Couldn't find submodule 0x%04x" % (submodule["id"]))
                subslot = Subslot(
                    slot=slot,
                    subslot=subslot,
                    id=submodule["id"],
                    submodule=g_submodule,
                    parameters=self._parse_parameters(g_submodule, submodule.get("parameters", {})),
                )
                has_input = subslot.submodule.input_data or not subslot.submodule.output_data
                if has_input:
                    subslot.input_data_offset = input(subslot.submodule.input_length)
                    subslot.input_iops_offset = input()
                    subslot.output_iocs_offset = output()
                if subslot.submodule.output_data:
                    subslot.output_data_offset = output(subslot.submodule.output_length)
                    subslot.output_iops_offset = output()
                    subslot.input_iocs_offset = input()
                s.subslots.append(subslot)
            out.append(s)
        self.slots = out
        self.input_frame_size = max(40, input_frame_offset)
        self.output_frame_size = max(40, output_frame_offset)

    @property
    def connect_blocks(self):
        input_api_objects = []
        input_iocs_objects = []
        output_api_objects = []
        output_iocs_objects = []
        expected_submodule_api_objects = []

        for slot in self.slots:
            expected_submodules = []
            for subslot in slot.subslots:
                if subslot.input_data_offset is not None:
                    input_api_objects.append(IOCRAPIObject(
                        SlotNumber=subslot.slot,
                        SubslotNumber=subslot.subslot,
                        FrameOffset=subslot.input_data_offset,
                    ))
                if subslot.output_iocs_offset is not None:
                    output_iocs_objects.append(IOCRAPIObject(
                        SlotNumber=subslot.slot,
                        SubslotNumber=subslot.subslot,
                        FrameOffset=subslot.output_iocs_offset,
                    ))
                if subslot.output_data_offset is not None:
                    output_api_objects.append(IOCRAPIObject(
                        SlotNumber=subslot.slot,
                        SubslotNumber=subslot.subslot,
                        FrameOffset=subslot.output_data_offset,
                    ))
                if subslot.input_iocs_offset is not None:
                    input_iocs_objects.append(IOCRAPIObject(
                        SlotNumber=subslot.slot,
                        SubslotNumber=subslot.subslot,
                        FrameOffset=subslot.input_iocs_offset,
                    ))
                data_description = []
                if subslot.input_data_offset is not None:
                    data_description.append(
                        ExpectedSubmoduleDataDescription(
                            DataDescription="Input",
                            LengthIOCS=1,
                            LengthIOPS=1,
                            SubmoduleDataLength=subslot.submodule.input_length,
                        )
                    )
                if subslot.output_data_offset is not None:
                    data_description.append(
                        ExpectedSubmoduleDataDescription(
                            DataDescription="Output",
                            LengthIOCS=1,
                            LengthIOPS=1,
                            SubmoduleDataLength=subslot.submodule.output_length,
                        )
                    )
                expected_submodules.append(
                    ExpectedSubmodule(
                        SubmoduleIdentNumber=subslot.submodule.ident,
                        SubslotNumber=subslot.subslot,
                        SubmoduleProperties_Type=("INPUT_OUTPUT" if len(data_description) == 2 else ("OUTPUT" if subslot.submodule.output_length else "INPUT")),
                        DataDescription=data_description,
                    )
                )
            expected_submodule_api_objects.append(ExpectedSubmoduleAPI(
                SlotNumber=slot.slot,
                ModuleIdentNumber=slot.module.ident,
                Submodules=expected_submodules,
            ))
        return [
            IOCRBlockReq(
                IOCRProperties_RTClass=0x2,
                IOCRType="InputCR",
                ReductionRatio=512, # FIXME
                WatchdogFactor=3, # FIXME
                DataHoldFactor=3, # FIXME
                DataLength=self.input_frame_size,
                FrameID=0x8001,
                IOCRReference=0x0001,
                APIs=[
                    IOCRAPI(
                        IODataObjects=input_api_objects,
                        IOCSs=input_iocs_objects,
                    ),
                ],
            ),
            IOCRBlockReq(
                IOCRProperties_RTClass=0x2,
                IOCRType="OutputCR",
                ReductionRatio=512, # FIXME
                WatchdogFactor=3, # FIXME
                DataHoldFactor=3, # FIXME
                DataLength=self.output_frame_size,
                FrameID=0x8002,
                IOCRReference=0x0002,
                APIs=[
                    IOCRAPI(
                        IODataObjects=output_api_objects,
                        IOCSs=output_iocs_objects,
                    ),
                ],
            ),
        ] + [
            ExpectedSubmoduleBlockReq(
                APIs=[
                    a
                ]
            )
            for a in expected_submodule_api_objects
        ]

    def crs(self, type: int) -> list[IOCRBlockReq]:
        return [block for block in self.connect_blocks if isinstance(block, IOCRBlockReq) and block.IOCRType == type]

    @property
    def input_crs(self):
        return self.crs(1)

    @property
    def output_crs(self):
        return self.crs(2)

    @property
    def parameter_values(self):
        for slot in self.slots:
            for subslot in slot.subslots:
                for index, value in subslot.parameters.items():
                    yield (slot.slot, subslot.subslot, index, value)

    @property
    def input_struct(self) -> tuple[str, tuple[int, int, str]]:
        format = ">"
        input_fields = []
        for slot in self.slots:
            for subslot in slot.subslots:
                for data_item in subslot.submodule.input_data:
                    format += data_item.data_type.format
                    input_fields.append((subslot.slot, subslot.subslot, data_item.name))
                if subslot.submodule.input_data or not subslot.submodule.output_data:
                    format += "B"
                    input_fields.append((subslot.slot, subslot.subslot, "IOPS"))
                if subslot.submodule.output_data:
                    format += "B"
                    input_fields.append((subslot.slot, subslot.subslot, "IOCS"))
        return format, input_fields

    @property
    def mqtt_server(self) -> str|None:
        return self.config.get("mqtt", {}).get("server")

    def mqtt_topic(self, type: str) -> str:
        return "%s/%s" % (self.config["mqtt"]["topic_prefix"], type)
