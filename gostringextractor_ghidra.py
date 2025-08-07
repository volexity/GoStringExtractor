# Construct Go strings from the string table
# @authors: Ivan Mladenov, Damien Cash
# @category: Golang
# @keybinding 
# @menupath 
# @toolbar 
# @runtime PyGhidra

# Python Imports
import json
from collections import namedtuple

# Ghidra Imports
import jpype
from ghidra.program.database.mem import MemoryMapDB
from ghidra.program.database.function import FunctionManagerDB
from ghidra.program.database.references import ReferenceDBManager
from docking.widgets.dialogs import InputDialog
from docking.widgets import SelectFromListDialog
from ghidra.features.bsim.gui.filters import MultiChoiceSelectionDialog
from javax.swing import * # noqa: F403
from java.util import HashSet, ArrayList
from java.util.function import Function
from ghidra.program.model.address import Address, GenericAddress
from ghidra.program.database import ProgramAddressFactory
from ghidra.program.model.symbol import Reference
from ghidra.program.flatapi import FlatProgramAPI

# Java definitions of byte and byte[] types
Byte = jpype.JByte
ByteArray = jpype.JArray(jpype.JByte)

PROJECT = state.getProject()
MEMORY: MemoryMapDB = currentProgram.getMemory()
FUNCTIONS: FunctionManagerDB = currentProgram.getFunctionManager()
REFERENCES: ReferenceDBManager = currentProgram.getReferenceManager()
ADDRESS: ProgramAddressFactory = currentProgram.getAddressFactory()
FPAPI: FlatProgramAPI = FlatProgramAPI(currentProgram)

"""This script is using a language name that appears in nearly all Golang
binaries due to the runtime syscall entry in a goroutine. This may turn out
to be a fairly brittle indicator for the location of the string table, so
other means may be necessary in future versions."""

# Bytes of "entersyscall"
magic_bytes = ByteArray([Byte(101), Byte(110), Byte(116),Byte(101), Byte(114), 
                         Byte(115), Byte(121), Byte(115), Byte(99), Byte(97),
                         Byte(108), Byte(108)])

options = namedtuple("options",
    [
        "outfile",
        "start_ea",
        "search_up",
        "search_down",
        "make_strs",
        "append",
        "filter",
        "package"
    ],
)
segment = namedtuple("segment", ["name", "start", "end"])
str_span = namedtuple("str_span", ["address", "length"])
reference = namedtuple("reference", ["address", "name"])
gostring = namedtuple("gostring", ["str", "refs"])

def find_segments() -> list[segment]:
    """Find suitable data segments to search for magic

    Returns:
        list[segment]: List of data segments to search
    """
    segs_to_search = []
    blocks = MEMORY.getBlocks()

    for block in blocks:
        name = block.getName()
        if ('rodata' in name) or ('data' in name):
            segs_to_search.append(segment(name, block.getStart(),
                                          block.getEnd()))

    return segs_to_search

def search_for_magic(seg: segment) -> GenericAddress:
    """Finds start address of magic bytes

    Returns:
        GenericAddress: Address of magic, if found.
    """    
    return MEMORY.findBytes(seg.start, seg.end, magic_bytes, None, True, None)

def xref_to_names(ref: Reference, depth: int) -> list[reference]:
    """Collects all functions which cross-reference the string

    Arguments:
        ref (Reference): Reference to a string
        depth (int): Depth of nested cross-reference

    Returns:
        list[references]: List of references whose root is a function
    """ 
    names = []
    ea = ref.getFromAddress()

    """Certain Go binaries have references with up to 5 levels of indirection 
    from code to the string, we stop searching after this"""
    if depth >= 5:
        return []

    name = FUNCTIONS.getFunctionContaining(ea)
    if name is not None:
        names.append(reference(ea, name))
        return names
    else:
        for ref in REFERENCES.getReferencesTo(ea):
            names += xref_to_names(ref, depth+1)
        return names

def mk_string(
    span: str_span, refs: list[reference], make_strings: bool
) -> gostring:
    """Converts bytes to unicode string for JSON and (optionally) Ghidra

    Arguments:
        span (str_span): Identified string in database
        refs (list[reference]): List of identified references to the string
        make_strings (bool): Whether to make strings in Ghidra database

    Returns:
        gostring: A string with its all of its references
    """
    if make_strings:
        # Clears out xrefs jammed inside the string
        for i in range(int(span.length)):
            newAddress: Address = span.address.add(i)
            if FPAPI.getDataAt(newAddress) is not None:
                try:
                    FPAPI.removeDataAt(newAddress)    
                except Exception:
                    print("Error cleaning out data for string.")
        FPAPI.createAsciiString(span.address, int(span.length))

    buffer = Byte[span.length]
    number = MEMORY.getBytes(span.address, buffer)

    if number != span.length:
        print(
            (f"Error creating string at {hex(span.address)}, with span"
             f"{span.length}. Continuing.")
        )
        return None

    bytestring = bytes(buffer)
    if refs:
        return gostring(bytestring.decode("raw_unicode_escape", 
                                          errors="backslashreplace"), refs)
    else:
        return None

def add_string(span: str_span, package: str, make_strings: bool) -> gostring:
    """Add string based on package filters

    Arguments:
        span (str_span): The string to add
        package (str): The package name to filter by
        make_strings (bool): Whether to make the string in Ghidra
    
    Returns:
        gostring: The added string (if it's not filtered)
    """
    refs = []
    for ea_ref in REFERENCES.getReferencesTo(span.address):
        refs += xref_to_names(ea_ref,0)

    if not package:
        return mk_string(span, refs, make_strings)
    else:
        pack_mark = package + '.'
        for x in refs:
            if pack_mark in x.name:
                return mk_string(span, refs, make_strings)
        return None

def add_strings(
    spans: list[str_span], package: str, make_strings: bool
) -> list[gostring]:
    """Add all strings based on package filters

    Arguments:
        spans (list[str_span]): The strings to add
        package (str): The package to filter by
        make_strings (bool): Whether to make the strings in Ghidra

    Returns:
        list[gostring]: List of successfully made strings
    """
    strs = []
    for span in spans:
        s = add_string(span, package, make_strings)
        if s is None:
            continue
        strs.append(s)

    return strs


def build_ref_up(
    ea_start: GenericAddress, span_start: int, seg: segment
) -> list[str_span]:
    """Collect all string references above the starting search address

    Arguments:
        ea_start (GenericAddress): The address to begin the search from
        span_start (int): The starting length of the string
        seg (segment): The segment to search the string in

    Returns:
        list[str_span]: List of string references found in the segment
    """
    results = []
    span = span_start
    ea_last = ea_start
    ea = ea_start.subtract(1)
    first_string = False

    while True:
        # Don't overrun the segment, Ghidra sometimes has missing addresses
        if ea.getOffset() <= seg.start.getOffset() + 4:
            break

        # Good? metric to end search, chain of 4 null bytes
        if (MEMORY.getByte(ea) 
            == MEMORY.getByte(ea.subtract(1)) 
            == MEMORY.getByte(ea.subtract(2)) 
            == MEMORY.getByte(ea.subtract(3)) 
            == 0):
           first_string = True
        
        # Grab first xref, kind of clunky
        referenced = None
        for ref in REFERENCES.getReferencesTo(ea):
            referenced = ref
            break

        if referenced is not None:
            # Update the span length if it's shorter than the previous one
            # This avoids the issue of unreferenced strings jammed inside
            if span > ea_last.subtract(ea):
                span = ea_last.subtract(ea)
            results.append(str_span(ea,span))
            
            # Reached the top of the string table
            if first_string:
                break

            ea_last = ea
            
        ea = ea.subtract(1)

    return results

def build_ref_down(
    ea_start: GenericAddress, span_start: int, seg: segment
) -> list[str_span]:
    """Collect all string references below the starting search address

    Arguments:
        ea_start (GenericAddress): The address to begin the search from
        span_start (int): The starting length of the string
        seg (segment): The segment to search the string in

    Returns:
        list[str_span]: List of string references found in the segment
    """
    results = []
    ea_last = ea_start
    ea = ea_start
    last_string = False

    while True:
        ea = ea.add(1)
        if ea >= seg.end:
            # This should never even come close to happening, better be safe
            break
        
        # Good? metric to end search, chain of 4 null bytes
        if (MEMORY.getByte(ea) == MEMORY.getByte(ea.add(1)) == 
            MEMORY.getByte(ea.add(2)) == MEMORY.getByte(ea.add(3)) == 0):
           last_string = True

        # Grab first xref, kind of clunky
        referenced = None
        for ref in REFERENCES.getReferencesTo(ea):
            referenced = ref
            break

        if referenced is not None:
            span = ea.subtract(ea_last)

            results.append(str_span(ea_last,span))
            
            if last_string:
                break

            ea_last = ea

    return results

def get_strings(opts: options, seg: segment) -> None:
    """Dump all strings from segment into a JSON file

    Arguments:
        opts (options): Options from user for string filtering/search
        seg (segment): Segment to collect strings from
    """
    eas = []
    if opts.search_up:
        eas += build_ref_up(opts.start_ea, len(magic_bytes), seg)
    if opts.search_down:
        eas += build_ref_down(opts.start_ea, len(magic_bytes), seg)

    package = None
    if opts.filter:
        package = opts.package

    strs = add_strings(
        sorted(eas,key=lambda x: x.address),
        package,
        opts.make_strs
    )

    # Convert GenericAddress to str to make it serializable
    converted_strs = [
        gostring(
            s.str,
            [reference(str(ref.address), str(ref.name)) for ref in s.refs]
        )
        for s in strs
    ]

    if opts.append:
        with open(opts.outfile,'r') as f:
            converted_strs = json.loads(f.read()) + converted_strs
    with open(opts.outfile,'w') as f:
        f.write(json.dumps(converted_strs, indent=2))

"""The Go string table, at least from versions 1.8 to 1.21, is length ordered.
This script works by using a string known to exist in the runtime functions of
these versions, and walking the string table forward and backward from that
point using IDA's cross-referencing feature as a hint to identify string
boundaries."""

"""Functional interface hack to add string conversion to Java from Python"""
@jpype.JImplements(Function)
class ToStrFunction:
    @jpype.JOverride
    def apply(self, value):
        return str(value)


def main() -> None:
    """Entry point to spawn GUI and then collect + dump all strings"""
    # Collect segments and look for "entersyscall" magic string
    segs = find_segments()
    for seg in segs:
        ea_match = search_for_magic(seg)
        if ea_match is not None:
            seg_match = seg
            break   # There should only be one non zero-terminated instance of
                    # the magic string in the binary.

    # Collect package names by using the function names
    packages = set()
    funcs = FUNCTIONS.getFunctions(True)
    for func in funcs:
        name = func.getName()
        if not name:
            print("Error: Found a function without a name!!!")
        if '.' in name:
            packages.add(name.split('.',2)[0])

    # Ghidra GUI
    # First dialog to setup output and search
    tool = state.getTool()
    proj_dir = str(state.getProject().getProjectLocator().getLocation())[1:]
    exe_name = currentProgram.getExecutablePath().split("/")[-1]

    id = InputDialog("Go Strings: Setup", ["Output File", "Start Address"], 
                     [proj_dir + exe_name + '_strs.json', 
                     "0x" + str(ea_match)])
    id.setPreferredSize(600, 400)
    tool.showDialog(id)

    if id.isCanceled():
        return
    input = id.getValues()
    outfile = input[0]
    start_ea = ADDRESS.getAddress(input[1])

    # Second dialog to setup search options
    choices = ArrayList(["Search Up", "Search Down", "Make Strings in Ghidra", 
                         "Append to Output File", "Filter by Package"])
    selected = HashSet(["Search Up", "Search Down", "Make Strings in Ghidra"])
    id = MultiChoiceSelectionDialog("GoStringExtractor: Options", choices, selected)
    tool.showDialog(id)

    # Set options aftere receiving user input
    input = id.getSelectedChoices()
    search_up = search_down = make_strs = append = filter = False
    if input is None: # equivalent check to isCanceled() for this dialog
        return
    for choice in input:
        match choice:
            case "Search Up":
                search_up = True
            case "Search Down":
                search_down = True
            case "Make Strings in Ghidra":
                make_strs = True
            case "Append to Output File":
                append = True
            case "Filter by Package":
                filter = True

    # Third dialog to choose package to search
    package = None
    if "Filter by Package" in input:
        try:
            func = ToStrFunction()
            pkgs = ArrayList(list(packages))
            id = SelectFromListDialog("GoStringExtractor: Package Filter", 
                                      "Select a Package", pkgs, func)
            package = id.selectFromList(pkgs, "GoStringExtractor: Package Filter",
                                        "Select a Package", func)
        except ValueError as ex:
            print("Caught Python Exception:", str(ex))

    opts = options(outfile, start_ea, search_up, search_down, make_strs, 
                   append, filter, package)

    get_strings(opts, seg_match)

if __name__ == "__main__":
    main()
