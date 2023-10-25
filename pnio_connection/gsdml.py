import sys
from enum import Enum, auto
from dataclasses import dataclass, field
from xml.etree.ElementTree import parse, Element

NS = {
    '': 'http://www.profibus.com/GSDML/2003/11/DeviceProfile',
}

class DataType(Enum):
    Unsigned8 = "Unsigned8"
    Unsigned16 = "Unsigned16"
    Unsigned32 = "Unsigned32"

    @property
    def size(self):
        if self == self.Unsigned8:
            return 1
        if self == self.Unsigned16:
            return 2
        if self == self.Unsigned32:
            return 4
        raise ValueError("unknown data type")

@dataclass
class DataItem:
    data_type: DataType
    text_id: str

@dataclass
class Submodule:
    id: str
    ident: int
    subslots: frozenset[int] | None
    input_data: list[DataItem] = field(default_factory=list)
    output_data: list[DataItem] = field(default_factory=list)

    @property
    def input_length(self):
        return sum(d.data_type.size for d in self.input_data)

    @property
    def output_length(self):
        return sum(d.data_type.size for d in self.output_data)

@dataclass
class Module:
    id: str
    ident: int
    slots: frozenset[int]
    submodules: list[Submodule]

    def get_submodule(self, id):
        for submodule in self.submodules:
            if submodule.id == id:
                return submodule

def parse_dataitem(el: Element) -> DataItem:
    return DataItem(
        data_type=DataType(el.get("DataType")),
        text_id=el.get("TextId"),
    )

def parse_slots(t: str) -> frozenset[int]:
    if ".." in t:
        min, max = [int(x, 0) for x in t.split("..")]
        return frozenset(range(min, max+1))
    return frozenset([int(x, 0) for x in t.split()])

def submodules(mod: Element) -> list[Submodule]:
    out = []
    for submodule in mod.findall("./VirtualSubmoduleList/VirtualSubmoduleItem", NS):
        out.append(Submodule(
            id=submodule.get("ID"),
            ident=int(submodule.get("SubmoduleIdentNumber"), 0),
            # spec says default is 1 if omitted
            subslots=parse_slots(submodule.get("FixedInSubslots", "1")),
            input_data=[parse_dataitem(e) for e in submodule.findall("./IOData/Input/DataItem", NS)],
            output_data=[parse_dataitem(e) for e in submodule.findall("./IOData/Output/DataItem", NS)],
        ))
    for submodule in mod.findall("./SystemDefinedSubmoduleList/*", NS):
        out.append(Submodule(
            id=submodule.get("ID"),
            ident=int(submodule.get("SubmoduleIdentNumber"), 0),
            subslots=parse_slots(submodule.get("SubslotNumber", "1")),
        ))
    return out

@dataclass
class GSDML:
    doc: Element
    dap: Element
    vendor_id: int
    device_id: int
    modules: list[Module]

    def __init__(self, path):
        self.doc = parse(path)

        dev_identity = self.doc.find(".//DeviceIdentity", NS)

        self.vendor_id = int(dev_identity.get("VendorID"), 0)
        self.device_id = int(dev_identity.get("DeviceID"), 0)

        self.dap = self.doc.find(".//DeviceAccessPointItem", NS)

        modules = [
            Module(
                id=self.dap.get("ID"),
                ident=int(self.dap.get("ModuleIdentNumber"), 0),
                slots=parse_slots(self.dap.get("FixedInSlots")),
                submodules=submodules(self.dap),
            ),
        ]

        for mir in self.dap.findall("./UseableModules/ModuleItemRef", NS):
            module = self.doc.find(".//ModuleItem[@ID='%s']" % (mir.get("ModuleItemTarget")), NS)
            modules.append(Module(
                id=module.get("ID"),
                ident=int(module.get("ModuleIdentNumber"), 0),
                slots=parse_slots(mir.get("AllowedInSlots")),
                submodules=submodules(module),
            ))
        self.modules = modules

    def get_module(self, id):
        for module in self.modules:
            if module.id == id:
                return module

if __name__ == "__main__":
    print(GSDML(sys.argv[1]))
