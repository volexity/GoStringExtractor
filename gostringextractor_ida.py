"""Construct Go strings from the string table."""

# Python Imports
import json
import os
from collections import namedtuple
from binascii import hexlify

# IDA Pro Imports
import ida_bytes
import ida_idaapi
from idaapi import BADADDR
from ida_nalt import STRTYPE_C
from ida_kernwin import Form
from ida_funcs import get_func_name
from ida_xref import get_first_dref_to
from idautils import DataRefsTo, Functions
from ida_segment import get_first_seg, get_next_seg, get_segm_name
from idc import get_idb_path

"""This script is using a language name that appears in nearly all golang
binaries due to the runtime's own localization functions. This may turn out 
to be a fairly brittle indicator for the location of the string table, so
other means may be necessary in future versions."""
magic_bytes = b'entersyscall'
magic_hex = hexlify(magic_bytes)
magic = (
    b' '.join([magic_hex[i:i+2] for i in range(0, len(magic_hex), 2)])
).decode()

options = namedtuple('options',
    [
        'outfile',
        'start_ea',
        'search_up',
        'search_down',
        'make_strs',
        'append',
        'filter',
        'package'
    ]
)
segment = namedtuple('segment', ['name', 'start', 'end'])
str_span = namedtuple('str_span', ['address', 'length'])
reference = namedtuple('reference', ['address', 'name'])
gostring = namedtuple('gostring', ['str', 'refs'])

##############################################################################
# Dialog definition
##############################################################################
class CMainDialog(Form):
    def __init__(self):
        s = r"""
GoStringExtractor

<OutputFile:{iOutFile}>
<#Address to start searching from#StartAddress:{iStartEa}>

Options:
<Search Up:{rDoUp}>
<Search Down:{rDoDown}>
<Make Strings in IDA:{rMakeStrs}>
<Append To Out File:{rAppend}>{cGroup1}>

Package Options:
<Filter by package:{rFilter}>{cGroup2}>

<Select a package:{iPackages}>
"""
        args = {
            "iOutFile": Form.FileInput(save=True, swidth=40,
                                       hlp="JSON file (*.json)"),
            "iStartEa": Form.NumericInput(tp=Form.FT_HEX, swidth=22),
            "cGroup1": Form.ChkGroupControl
            (
                (
                    "rDoUp",
                    "rDoDown",
                    "rMakeStrs",
                    "rAppend"
                )
            ),
            "cGroup2":Form.ChkGroupControl
            (
                (
                    "rFilter",
                )
            ),
            "iPackages": Form.DropdownListControl(swidth=40)
        }
        Form.__init__(self, s, args)

    def set_defaults(self,start_ea,packages) -> None:
        self.packages = packages
        self.iOutFile.value = (os.path.splitext(get_idb_path())[0] # noqa: F821
                              + '_strs.json')
        self.iStartEa.value = start_ea
        self.rDoUp.checked = True
        self.rDoDown.checked = True
        self.rMakeStrs.checked = False
        self.rAppend.checked = False
        self.rFilter.checked = False
        self.iPackages.set_items(packages)
            
    def get_options(self) -> options:
        if self.rAppend.checked and not os.path.isfile(self.iOutFile.value):
            raise(ValueError("If append is checked, you must provide an "
                             "existing JSON file."))

        if self.packages:
            package = self.packages[self.iPackages.value]
            pack_filter = self.rFilter.checked
        else:
            package = None
            pack_filter = False
        return options(
            self.iOutFile.value,
            self.iStartEa.value,
            self.rDoUp.checked,
            self.rDoDown.checked,
            self.rMakeStrs.checked,
            self.rAppend.checked,
            pack_filter,
            package
        )
##############################################################################

def get_packages_from_functions() -> set[str]:
    """Uses function names to collect all packages

    Returns:
        set[str]: Set of all the package names
    """
    packages = set()

    for ea in Functions():
        name = get_func_name(ea)
        if not name:
            print("Error: Found a function without a name!!!")
        if '.' in name:
            packages.add(name.split('.',2)[0])

    return packages

def find_segments() -> list[segment]:
    """Find suitable data segments to search for magic

    Returns:
        list[segment]: List of data segments to search
    """
    segs_to_search = []

    s = get_first_seg()
    while s is not None:
        name = get_segm_name(s)
        if ('rodata' in name) or ('data' in name):
            segs_to_search.append(segment(name,s.start_ea,s.end_ea))
        s = get_next_seg(s.start_ea)

    return segs_to_search

def search_for_magic(seg: segment) -> int:
    """Finds start address of magic bytes

    Returns:
        int: Address of magic, if found.
    """ 
    result = None
    pat = ida_bytes.compiled_binpat_vec_t()
    if ida_bytes.parse_binpat_str(pat, seg.start, magic, 16, 0) is not None:
        # Second value is index of matched pattern in the vector, discard
        ea, _ = ida_bytes.bin_search(
            seg.start, seg.end, pat, ida_bytes.BIN_SEARCH_CASE
        )
        if ea != BADADDR and ida_bytes.get_byte(ea+len(magic_bytes)) != 0:
            result = ea
    return result

def xref_to_names(ea: int, depth: int) -> list[reference]:
    """Collects all functions which cross-reference the string

    Arguments:
        ref (Reference): Reference to a string
        depth (int): Depth of nested cross-reference

    Returns:
        list[references]: List of references whose root is a function
    """
    names = []

    # Certain Go binaries have references with up to 5 levels of indirection 
    # from code to the string, we stop searching after this
    if depth >= 5:
        return []

    n = get_func_name(ea)
    if n is not None:
        names.append(reference(ea,n))
        return names
    else:
        for ref in DataRefsTo(ea):
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
        ida_bytes.del_items(span.address)
        ida_bytes.create_strlit(span.address,span.length,STRTYPE_C)

    d = ida_bytes.get_bytes(span.address,span.length)
    if d is None:
        print(
            (f"Error creating string at {hex(span.address)}, with span"
             f"{span.length}. Continuing.")
        )
        return None
    
    return gostring(d.decode("raw_unicode_escape", errors="backslashreplace"),
                    refs)

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
    for ea_ref in DataRefsTo(span.address):
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

def build_ref_up(ea_start: int, span_start: int, seg: segment) -> list[str_span]:
    """Collect all string references above the starting search address

    Arguments:
        ea_start (int): The address to begin the search from
        span_start (int): The starting length of the string
        seg (segment): The segment to search the string in

    Returns:
        list[str_span]: List of string references found in the segment
    """
    results = []
    span = span_start
    ea_last = ea_start
    ea = ea_start - 1
    first_string = False
    while True:
        if ea <= seg.start:
            break

        # Good? metric to end search, chain of 4 null bytes
        if (ida_bytes.get_byte(ea) 
            == ida_bytes.get_byte(ea - 1) 
            == ida_bytes.get_byte(ea - 2) 
            == ida_bytes.get_byte(ea - 3) 
            == 0):
           first_string = True
        
        if get_first_dref_to(ea) != BADADDR:
            # Update the span length if it's shorter than the previous one
            # This avoids the issue of unreferenced strings jammed inside
            if span > ea_last - ea:
                span = ea_last - ea
            results.append(str_span(ea, span))

            if first_string:
                break

            ea_last = ea

        ea -= 1
    return results

def build_ref_down(ea_start: int, span_start: int, seg: segment) -> list[str_span]:
    """Collect all string references below the starting search address

    Arguments:
        ea_start (int): The address to begin the search from
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
        ea += 1
        if ea >= seg.end:
            # This should never even come close to happening,
            # but better safe than sorry
            break
        
        # Good? metric to end search, chain of 4 null bytes
        if (ida_bytes.get_byte(ea) == ida_bytes.get_byte(ea + 1) == 
            ida_bytes.get_byte(ea + 2) == ida_bytes.get_byte(ea + 3) == 0):
           last_string = True

        if get_first_dref_to(ea) != BADADDR:
            span = ea - ea_last

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
        eas += build_ref_up(opts.start_ea,len(magic_bytes), seg)
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

    if opts.append:
        with open(opts.outfile,'r') as f:
            strs = json.loads(f.read()) + strs
    with open(opts.outfile,'w') as f:
        f.write(json.dumps(strs, indent=2))


"""The Go string table, at least from versions 1.8 to 1.21, is length ordered.
This script works by using a string known to exist in the runtime functions
of these versions, and walking the string table forward and backward from
that point using IDA's cross-referencing feature as a hint to identify
string boundaries."""
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

    packages = list(get_packages_from_functions())

    f = CMainDialog()
    f.Compile()
    f.set_defaults(ea_match, packages)
    ok = f.Execute()
    if ok == 1:
        # Filter strings when building
        opts = f.get_options()
        get_strings(opts, seg_match)
    elif ok == 0:
        # UI Canceled do nothing
        pass
    else:
        raise(ValueError(f"Invalid 'ok' option: {ok}"))
    f.Free()

# IDA Pro Plugin boilerplate
class GoStringExtractorPlugmod(ida_idaapi.plugmod_t):
    def __del__(self):
        print(">>> GoStringExtractorPlugmod: destructor called.")
    
    def run(self, arg):
        print(">>> GoStringExtractorPlugmod.run() called.")
        main()
        

class GoStringExtractorPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_UNL | ida_idaapi.PLUGIN_MULTI
    comment = "GoStringExtractor IDA Pro Plugin"
    help = "This program finds and constructs the strings in a Go binary."
    wanted_name = "GoStringExtractor"
    wanted_hotkey = "Shift-S"

    def init(self):
        print(">>> GoStringExtractorPlugin: Init called.")
        return GoStringExtractorPlugmod()

def PLUGIN_ENTRY():
    return GoStringExtractorPlugin()

