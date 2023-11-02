import sys
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Optional
from xml.etree.ElementTree import parse, Element, ElementTree

NS = {
    '': 'http://www.profibus.com/GSDML/2003/11/DeviceProfile',
}

class DataType(Enum):
    Unsigned8 = "Unsigned8"
    Unsigned16 = "Unsigned16"
    Unsigned32 = "Unsigned32"
    Bit = "Bit"

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
    name: str

@dataclass
class ParameterField:
    offset: int|tuple[int, int]
    data_type: DataType
    name: str
    enum: Optional[dict[str, int]]

@dataclass
class Parameter:
    index: int
    length: int
    name: str
    fields: list[ParameterField]

@dataclass
class Submodule:
    id: str
    ident: int
    subslots: frozenset[int] | None
    input_data: list[DataItem] = field(default_factory=list)
    output_data: list[DataItem] = field(default_factory=list)
    parameters: list[Parameter] = field(default_factory=list)

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

def parse_slots(t: str) -> frozenset[int]:
    if ".." in t:
        min, max = [int(x, 0) for x in t.split("..")]
        return frozenset(range(min, max+1))
    return frozenset([int(x, 0) for x in t.split()])

@dataclass
class GSDML:
    doc: ElementTree
    dap: Element
    vendor_id: int
    device_id: int
    modules: list[Module]
    text: dict[str, str]
    value_list: dict[str, dict[str, int]]

    def __init__(self, path):
        self.doc = parse(path)

        dev_identity = self.doc.find(".//DeviceIdentity", NS)

        self.vendor_id = int(dev_identity.get("VendorID"), 0)
        self.device_id = int(dev_identity.get("DeviceID"), 0)

        self.dap = self.doc.find(".//DeviceAccessPointItem", NS)

        self.text = {}
        for el in self.doc.findall(".//ExternalTextList/PrimaryLanguage/Text", NS):
            self.text[el.get("TextId")] = el.get("Value")

        self.value_list = {}
        for value_item in self.doc.findall(".//ValueList/ValueItem", NS):
            self.value_list[value_item.get("ID")] = {
                self.text[a.get("TextId")]: int(a.get("Content"), 0)
                for a in value_item.findall("./Assignments/Assign", NS)
            }

        modules = [
            Module(
                id=self.dap.get("ID"),
                ident=int(self.dap.get("ModuleIdentNumber"), 0),
                slots=parse_slots(self.dap.get("FixedInSlots")),
                submodules=self._submodules(self.dap),
            ),
        ]

        for mir in self.dap.findall("./UseableModules/ModuleItemRef", NS):
            module = self.doc.find(".//ModuleItem[@ID='%s']" % (mir.get("ModuleItemTarget")), NS)
            modules.append(Module(
                id=module.get("ID"),
                ident=int(module.get("ModuleIdentNumber"), 0),
                slots=parse_slots(mir.get("AllowedInSlots")),
                submodules=self._submodules(module),
            ))
        self.modules = modules

    def get_module(self, id):
        for module in self.modules:
            if module.id == id:
                return module

    def _parameters(self, submod: Element) -> list[Parameter]:
        out = []
        for parameter in submod.findall("./RecordDataList/ParameterRecordDataItem", NS):
            fields = []
            for field in parameter.findall("./Ref", NS):
                offset=int(field.get("ByteOffset", "0"), 0)
                data_type=DataType(field.get("DataType"))
                if data_type == DataType.Bit:
                    offset=(offset, int(field.get("BitOffset", "0"), 0))
                enum = None
                if value_item := field.get("ValueItemTarget"):
                    enum = self.value_list[value_item]
                fields.append(ParameterField(
                    offset=offset,
                    data_type=data_type,
                    name=self.text[field.get("TextId")],
                    enum=enum,
                ))
            out.append(Parameter(
                index=int(parameter.get("Index"), 0),
                length=int(parameter.get("Length"), 0),
                name=self.text[parameter.find("Name", NS).get("TextId")],
                fields=fields,
            ))
        return out

    def _submodules(self, mod: Element) -> list[Submodule]:
        out = []
        for submodule in mod.findall("./VirtualSubmoduleList/VirtualSubmoduleItem", NS):
            out.append(Submodule(
                id=submodule.get("ID"),
                ident=int(submodule.get("SubmoduleIdentNumber"), 0),
                # spec says default is 1 if omitted
                subslots=parse_slots(submodule.get("FixedInSubslots", "1")),
                input_data=[self._parse_dataitem(e) for e in submodule.findall("./IOData/Input/DataItem", NS)],
                output_data=[self._parse_dataitem(e) for e in submodule.findall("./IOData/Output/DataItem", NS)],
                parameters=self._parameters(submodule),
            ))
        for submodule in mod.findall("./SystemDefinedSubmoduleList/*", NS):
            out.append(Submodule(
                id=submodule.get("ID"),
                ident=int(submodule.get("SubmoduleIdentNumber"), 0),
                subslots=parse_slots(submodule.get("SubslotNumber", "1")),
            ))
        return out

    def _parse_dataitem(self, el: Element) -> DataItem:
        text_id=el.get("TextId")
        return DataItem(
            data_type=DataType(el.get("DataType")),
            text_id=text_id,
            name=self.text[text_id],
        )

if __name__ == "__main__":
    print(GSDML(sys.argv[1]))
