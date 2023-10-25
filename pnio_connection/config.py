import os.path
import yaml

from .gsdml import GSDML, Module
from .pnio_rpc import ExpectedSubmodule, ExpectedSubmoduleAPI, ExpectedSubmoduleBlockReq, IOCRAPIObject, IOCRAPI, IOCRBlockReq

class ConfigReader:
    def __init__(self, path: str):
        self.config = yaml.safe_load(open(path))
        self.gsdml = GSDML(os.path.join(os.path.dirname(path), self.config["gsdml"]))

    @property
    def connect_blocks(self):
        input_frame_offset = output_frame_offset = 0

        input_api_objects = []
        input_iocs_objects = []
        output_api_objects = []
        output_iocs_objects = []

        for slot, module in sorted(self.config["slots"].items()):
            g_module = self.gsdml.get_module(module["id"])
            for subslot, submodule in sorted(module.get("subslots", {
                    1: {
                        "id": g_module.submodules[0].id,
                        "parameters": module.get("parameters", {}),
                    },
            }).items()):
                g_submodule = g_module.get_submodule(submodule["id"])
                if g_submodule.input_data:
                    input_api_objects.append(IOCRAPIObject(
                        SlotNumber=slot,
                        SubslotNumber=subslot,
                        FrameOffset=input_frame_offset,
                    ))
                    input_frame_offset += g_submodule.input_length + 1
                    output_iocs_objects.append(IOCRAPIObject(
                        SlotNumber=slot,
                        SubslotNumber=subslot,
                        FrameOffset=output_frame_offset,
                    ))
                    output_frame_offset += 1
                if g_submodule.output_data:
                    output_api_objects.append(IOCRAPIObject(
                        SlotNumber=slot,
                        SubslotNumber=subslot,
                        FrameOffset=output_frame_offset,
                    ))
                    output_frame_offset += g_submodule.output_length + 1
                    input_iocs_objects.append(IOCRAPIObject(
                        SlotNumber=slot,
                        SubslotNumber=subslot,
                        FrameOffset=input_frame_offset,
                    ))
                    input_frame_offset += 1
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
        ]
