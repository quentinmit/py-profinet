from dataclasses import dataclass
import os.path
from typing import Dict, List
import yaml

from .gsdml import GSDML, Module, Submodule
from .pnio_rpc import ExpectedSubmodule, ExpectedSubmoduleAPI, ExpectedSubmoduleBlockReq, ExpectedSubmoduleDataDescription, IOCRAPIObject, IOCRAPI, IOCRBlockReq

@dataclass
class Subslot:
    slot: int
    subslot: int
    id: int
    submodule: Submodule
    parameters: Dict[int, bytes]

@dataclass
class Slot:
    slot: int
    id: int
    module: Module
    subslots: List[Subslot]

class ConfigReader:
    def __init__(self, path: str):
        self.config = yaml.safe_load(open(path))
        self.gsdml = GSDML(os.path.join(os.path.dirname(path), self.config["gsdml"]))

    @property
    def slots(self) -> List[Slot]:
        out = []
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
                s.subslots.append(Subslot(
                    slot=slot,
                    subslot=subslot,
                    id=submodule["id"],
                    submodule=g_submodule,
                    # TODO: parameters
                    parameters={},
                ))
            out.append(s)
        return out

    @property
    def connect_blocks(self):
        input_frame_offset = output_frame_offset = 0

        input_api_objects = []
        input_iocs_objects = []
        output_api_objects = []
        output_iocs_objects = []
        expected_submodule_api_objects = []

        for slot in self.slots:
            expected_submodules = []
            for subslot in slot.subslots:
                has_input = subslot.submodule.input_data or not subslot.submodule.output_data
                if has_input:
                    input_api_objects.append(IOCRAPIObject(
                        SlotNumber=subslot.slot,
                        SubslotNumber=subslot.subslot,
                        FrameOffset=input_frame_offset,
                    ))
                    input_frame_offset += subslot.submodule.input_length + 1
                    output_iocs_objects.append(IOCRAPIObject(
                        SlotNumber=subslot.slot,
                        SubslotNumber=subslot.subslot,
                        FrameOffset=output_frame_offset,
                    ))
                    output_frame_offset += 1
                if subslot.submodule.output_data:
                    output_api_objects.append(IOCRAPIObject(
                        SlotNumber=subslot.slot,
                        SubslotNumber=subslot.subslot,
                        FrameOffset=output_frame_offset,
                    ))
                    output_frame_offset += subslot.submodule.output_length + 1
                    input_iocs_objects.append(IOCRAPIObject(
                        SlotNumber=subslot.slot,
                        SubslotNumber=subslot.subslot,
                        FrameOffset=input_frame_offset,
                    ))
                    input_frame_offset += 1
                data_description = []
                if has_input:
                    data_description.append(
                        ExpectedSubmoduleDataDescription(
                            DataDescription="Input",
                            LengthIOCS=1,
                            LengthIOPS=1,
                            SubmoduleDataLength=subslot.submodule.input_length,
                        )
                    )
                if subslot.submodule.output_length:
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
                DataLength=max(input_frame_offset, 40),
                FrameID=0x8001,
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
                DataLength=max(output_frame_offset, 40),
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

    @property
    def parameter_values(self):
        for slot in self.slots:
            for subslot in slot.subslots:
                for index, value in subslot.parameters.items():
                    yield (slot.slot, subslot.subslot, index, value)
