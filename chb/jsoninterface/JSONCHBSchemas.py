# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2023  Aarno Labs LLC
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# ------------------------------------------------------------------------------
"""Common schemas used throughout the binary analyzer python api."""

from typing import Any, Dict, Optional, TYPE_CHECKING


def prop_kind(name: str) -> Dict[str, Any]:
    kprop: Dict[str, Any] = {}
    kprop["type"] = "string"
    kprop["enum"] = [name]
    return kprop


def txtrep() -> Dict[str, str]:
    t: Dict[str, str] = {}
    t["type"] = "string"
    t["description"] = "suggested textual representation"
    return t


def refdef(name: str) -> Dict[str, str]:
    r: Dict[str, str] = {}
    r["$ref"] = "#/$defs/" + name
    return r


def strtype(desc: Optional[str] = None) -> Dict[str, str]:
    s: Dict[str, str] = {}
    s["type"] = "string"
    if desc is not None:
        s["description"] = desc
    return s


def intvalue(desc: Optional[str] = None) -> Dict[str, Any]:
    v: Dict[str, str] = {}
    v["type"] = "integer"
    if desc is not None:
        v["description"] = desc
    return v


stackpointeroffset = {
    "name": "stackpointeroffset",
    "title": "stackpointer offset",
    "description": (
        "value or range of values of the stack pointer "
        + "relative to the value at the function entry, "
        + "as determined by the analysis, or unknown"),
    "type": "object",
    "oneOf": [
        {
            "type": "object",
            "description": "typically used for unknown value",
            "required": ["kind", "txtrep"],
            "properties": {
                "kind": prop_kind("unb-itv"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": "single (usually negative) value",
            "required": ["kind", "value", "txtrep"],
            "properties": {
                "kind": prop_kind("civ"),
                "value": intvalue(),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": (
                "closed interval specified by minimum and maximum value"),
            "required": ["kind", "lb", "ub", "txtrep"],
            "properties": {
                "kind": prop_kind("itv"),
                "lb": intvalue(desc="lower-bound of offset value"),
                "ub": intvalue(desc="upper-bound of offset value"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": ("right open interval specified by lower bound"),
            "required": ["kind", "lb", "txtrep"],
            "properties": {
                "kind": prop_kind("lb-itv"),
                "lb": intvalue(desc="lower-bound on offset value"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "descripotion": ("left open interval specified by upper bound"),
            "required": ["kind", "ub", "txtrep"],
            "properties": {
                "kind": prop_kind("ub-itv"),
                "ub": intvalue(desc="upper-bound on offset value"),
                "txtrep": txtrep()
            }
        }
    ]
}


assemblyinstruction = {
    "name": "assemblyinstruction",
    "title": "assembly instruction",
    "description": (
        "Single assembly instruction at a given address within a function "
        + "annotated with analysis information"),
    "type": "object",
    "properties": {
        "addr": {
            "type": "array",
            "description": (
                "list of context addresses within the function "
                + "instruction address last"),
            "items": strtype(desc="hex address")
        },
        "stackpointer": refdef("stackpointeroffset"),
        "bytes": strtype(
            desc="hexadecimal representation of the instruction bytes"),
        "opcode": {
            "type": "array",
            "description": (
                "standard assembly instruction representation, possibly broken in "
                + "opcode part and operands part for better formatting"),
            "items": strtype()
        },
        "annotation": strtype(
            desc="representation of instruction semantics using invariants")
    }
}


assemblyblock = {
    "name": "assemblyblock",
    "title": "assembly block",
    "description": (
        "Range of instructions within a function that form a basic block"),
    "type": "object",
    "properties": {
        "startaddr": strtype(
            desc="hexaddress of the first instruction of the block"),
        "endaddr": strtype(
            desc=(
                "hexaddress of the (syntactically) last instruction of the "
                + "block. Note that this would be the address of the delay "
                + "slot for a MIPS assembly block, which is not the last "
                + "instruction to be executed")),
        "instructions": {
            "type": "array",
            "description": "list of assembly instructions contained in the block",
            "items": refdef("assemblyinstruction")
        }
    }
}


assemblyfunction = {
    "name": "assemblyfunction",
    "title": "assembly function",
    "description": ("Collection of basic blocks that make up a function"),
    "type": "object",
    "properties": {
        "name": strtype(
            desc=(
                "(optional) name of the function from symbol information "
                + "or user-provided")),
        "faddr": strtype(
            desc=(
                "hexaddress of function entry point. Note that this address "
                + "is not necessarily the lowest address of the function.")),
        "md5hash": strtype(
            desc=(
                "md5 hash of the hex-encoded bytes of the function instructions")),
        "basicblocks": {
            "type": "array",
            "description": ("list of basic blocks included in the function"),
            "items": refdef("assemblyblock")
        }
    }
}


memoryoffset = {
    "name": "memoryoffset",
    "title": "memory offset",
    "description": "(possibly symbolic) offset in bytes from a memory base",
    "type": "object",
    "oneOf": [
        {
            "type": "object",
            "description": "no offset",
            "required": ["kind"],
            "properties": {
                "kind": prop_kind("none")
            }
        },
        {
            "type": "object",
            "description": "constant numerical offset",
            "required": ["kind", "value", "txtrep"],
            "properties": {
                "kind": prop_kind("cv"),
                "value": intvalue(desc="offset value in bytes"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": "constant numerical offset with suboffset",
            "required": ["kind", "value", "suboffset", "txtrep"],
            "properties": {
                "kind": prop_kind("cvo"),
                "value": intvalue(desc="offset value in bytes"),
                "suboffset": {"$ref": "#"},
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": "index offset with variable and element size",
            "required": ["kind", "ixvar", "elsize", "txtrep"],
            "properties": {
                "kind": prop_kind("iv"),
                "ixvar": refdef("xvariable"),
                "elsize": intvalue(desc="size of element indexed"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": "index offset with suboffset",
            "required": ["kind", "ixvar", "elsize", "suboffset", "txtrep"],
            "properties": {
                "kind": prop_kind("ivo"),
                "ixvar": refdef("xvariable"),
                "elsize": intvalue(desc="size of element indexed"),
                "suboffset": {"$ref": "#"},
                "txtrep": txtrep()
            }
        }
    ]
}


memorybase = {
    "name": "memorybase",
    "title": "memory base",
    "description": "(symbolic) pointer to base of memory region",
    "type": "object",
    "oneOf": [
        {
            "type": "object",
            "description": "known base: function stack frame or global",
            "required": ["stack"],
            "properties": {
                "stack": {
                    "type": "string",
                    "enum": ["local", "allocated", "realigned", "global"]
                }
            }
        },
        {
            "type": "object",
            "description": "pointer contained in fixed-value variable",
            "required": ["ptrvar"],
            "properties": {
                "ptrvar": refdef("xvariable")
            }
        },
        {
            "type": "object",
            "description": "global base or unknown",
            "required": ["other"],
            "properties": {
                "other": {
                    "type": "string",
                    "enum": ["global", "unknown"]
                }
            }
        }
    ]
}


auxvariable = {
    "name": "auxvariable",
    "title": "auxiliary variable",
    "description": "variable with a fixed symbolic value",
    "type": "object",
    "oneOf": [
        {
            "type": "object",
            "description": "value of the register upon function entry",
            "required": ["kind", "register", "txtrep"],
            "properties": {
                "kind": prop_kind("irv"),
                "register": strtype(desc="name of register"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": "value of memory location upon function entry",
            "required": ["kind", "memvar", "txtrep"],
            "properties": {
                "kind": prop_kind("imv"),
                "memvar": refdef("xvariable"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": "value of variable frozen at test location",
            "required": ["kind", "testaddr", "jumpaddr", "testvar", "txtrep"],
            "properties": {
                "kind": prop_kind("ftv"),
                "testaddr": strtype(desc="hex address of test location"),
                "jumpaddr": strtype(desc="hex address of conditional branch"),
                "testvar": refdef("xvariable"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": "value of return value from a function call",
            "required": ["kind", "callsite", "calltarget", "txtrep"],
            "properties": {
                "kind": prop_kind("frv"),
                "callsite": strtype(desc="hexaddress of function call site"),
                "calltarget": strtype(desc="name of function called"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": "memory address",
            "required": ["kind", "base", "offset", "txtrep"],
            "properties": {
                "kind": prop_kind("ma"),
                "base": refdef("memorybase"),
                "offset": refdef("memoryoffset"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": "symbolic representation of expression",
            "required": ["kind", "expr", "txtrep"],
            "properties": {
                "kind": prop_kind("svx"),
                "expr": refdef("xexpression"),
                "txtrep": txtrep()
            }
        }
    ]
}


xconstant = {
    "name": "xconstant",
    "title": "constant value",
    "description": "constant value in expression",
    "type": "object",
    "oneOf": [
        {
            "type": "object",
            "description": "integer constant",
            "required": ["kind", "value"],
            "properties": {
                "kind": prop_kind("icst"),
                "value": intvalue()
            }
        },
        {
            "type": "object",
            "description": "integer constant string address",
            "required": ["kind", "value", "stringref"],
            "properties": {
                "kind": prop_kind("strcst"),
                "value": intvalue(),
                "stringref": strtype(desc="string at numerical address")
            }
        }
    ]
}


xvariable = {
    "name": "xvariable",
    "title": "variable",
    "description": "variable with or without denotation",
    "type": "object",
    "oneOf": [
        {
            "type": "object",
            "description": "temporary variable without denotation",
            "required": ["kind", "temp", "txtrep"],
            "properties": {
                "kind": prop_kind("temp"),
                "temp": strtype(),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": "memory variable",
            "required": ["kind", "base", "offset", "size", "txtrep"],
            "properties": {
                "kind": prop_kind("memvar"),
                "base": refdef("memorybase"),
                "offset": refdef("memoryoffset"),
                "size": intvalue(desc="size of variable in bytes"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": "register variable",
            "required": ["kind", "register", "txtrep"],
            "properties": {
                "kind": prop_kind("regvar"),
                "register": strtype(desc="name of register"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": "variable with a fixed (possibly symbolic) value",
            "required": ["kind", "fxdval", "txtrep"],
            "properties": {
                "kind": prop_kind("fxd"),
                "fxdval": refdef("auxvariable"),
                "txtrep": txtrep()
            }
        }
    ]
}


xexpression = {
    "name": "xexpression",
    "title": "symbolic expression",
    "description": "native representation expression",
    "type": "object",
    "oneOf": [
        {
            "type": "object",
            "description": "constant expression",
            "required": ["kind", "cst", "txtrep"],
            "properties": {
                "kind": prop_kind("xcst"),
                "cst": refdef("xconstant"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": "variable",
            "required": ["var", "txtrep"],
            "properties": {
                "kind": prop_kind("xvar"),
                "var": refdef("xvariable"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": "compound expression",
            "required": ["kind", "operator", "operands", "txtrep"],
            "properties": {
                "kind": prop_kind("xop"),
                "operator": strtype(desc="operation performed"),
                "operands": {
                    "type": "array",
                    "description": "list of operands (usually one or two)",
                    "items": {"$ref": "#/$defs/xexpression"}
                },
                "txtrep": txtrep()
            }
        }
    ]
}


linearequality = {
    "name": "linearequality",
    "title": "linear equality",
    "description": "linear equality of the form sum(a_i . x_i) = c",
    "type": "object",
    "required": ["constant", "coeffs", "factors", "txtrep"],
    "properties": {
        "constant": intvalue(desc="constant factor"),
        "coeffs": {
            "type": "array",
            "items": intvalue(desc="coefficient a_i (may be 0)")
        },
        "factors": {
            "description": "factors x_i",
            "type": "array",
            "items": refdef("xvariable")
        },
        "txtrep": txtrep()
    }
}


nonrelationalvalue = {
    "name": "nonrelationalvalue",
    "title": "non-relational value",
    "description": "symbolic constant",
    "type": "object",
    "oneOf": [
        {
            "type": "object",
            "description": "numeric value",
            "required": ["kind", "value", "txtrep"],
            "properties": {
                "kind": prop_kind("civ"),
                "value": intvalue(desc="constant singleton value"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": "closed range of values",
            "required": ["kind", "lb", "ub", "txtrep"],
            "properties": {
                "kind": prop_kind("itv"),
                "lb": intvalue(desc="lowerbound (inclusive) of range"),
                "ub": intvalue(desc="upperbound (inclusive) of range"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": "lower-bounded, half-open range of values",
            "required": ["kind", "lb", "txtrep"],
            "properties": {
                "kind": prop_kind("lb-itv"),
                "lb": intvalue(desc="lowerbound of half-open range"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": "upper-bounded, half-open range of values",
            "required": ["kind", "ub", "txtrep"],
            "properties": {
                "kind": prop_kind("ub-itv"),
                "ub": intvalue(desc="upperbound of half-open range"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": "base with numeric constant offset",
            "required": ["kind", "base", "value", "txtrep"],
            "properties": {
                "kind": prop_kind("b-civ"),
                "base": strtype(desc="symbolic base address"),
                "value": intvalue(desc="offset (in bytes) from base address"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": "base with bounded range of numeric offsets",
            "required": ["kind", "base", "lb", "ub", "txtrep"],
            "properties": {
                "kind": prop_kind("b-itv"),
                "base": strtype(desc="symbolic base address"),
                "lb": intvalue(desc=(
                    "lowerbound (inclusive) of offset range (in bytes)")),
                "ub": intvalue(desc=(
                    "upperbound (inclusive) of offset range (in bytes)")),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": "half-open range of address values",
            "required": ["kind", "base", "lb", "txtrep"],
            "properties": {
                "kind": prop_kind("b-lb-itv"),
                "base": strtype(desc="name of a base variable"),
                "lb": intvalue(desc="lower-bound of the range"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": "half-open range of values",
            "required": ["kind", "base", "ub", "txtrep"],
            "properties": {
                "kind": prop_kind("b-ub-itv"),
                "base": strtype(desc="name of a base variable"),
                "ub": intvalue(desc="upper-bound of the range"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": "base only with unbounded interval",
            "required": ["kind", "txtrep"],
            "properties": {
                "kind": prop_kind("b-unb"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": "symbolic expression",
            "required": ["kind", "sym-expr", "txtrep"],
            "properties": {
                "kind": prop_kind("sx"),
                "sym-expr": refdef("xexpression"),
                "txtrep": txtrep()
            }
        }
    ]
}


invariantfact = {
    "name": "invariantfact",
    "title": "invariant fact",
    "description": (
        "Assertion about the state at a particular program location (address)"),
    "type": "object",
    "oneOf": [
        {
            "type": "object",
            "description": (
                "assertion that location is unreachable, with domain that "
                + "reached that conclusion"),
            "required": ["kind", "domain", "txtrep"],
            "properties": {
                "kind": prop_kind("unr"),
                "domain": strtype(desc="domain with bottom result"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": (
                "variable has or does not have the same value as the value at "
                "function entry"),
            "required": [
                "kind", "relation", "var", "initval", "txtrep"],
            "properties": {
                "kind": prop_kind("ival"),
                "relation": {
                    "type": "string",
                    "enum": ["equals", "not-equals"]
                },
                "var": refdef("xvariable"),
                "initval": refdef("xvariable"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": (
                "relationship between value of testvariable at test location "
                + "and jump location (for evaluation of branch predicate)"),
            "required": [
                "kind", "testaddr", "jumpaddr", "testvar", "testval", "txtrep"],
            "properties": {
                "kind": prop_kind("tst"),
                "testaddr": strtype(
                    desc="hex address of instruction setting the condition codes"),
                "jumpaddr": strtype(
                    desc="hex address of conditional branch instruction"),
                "testvar": refdef("xvariable"),
                "testval": refdef("xvariable"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": "variable equality with non-relational value",
            "required": ["kind", "nrv", "var", "nrv", "txtrep"],
            "properties": {
                "kind": prop_kind("nrv"),
                "var": refdef("xvariable"),
                "nrv": refdef("nonrelationalvalue"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": (
                "location is unreachable; name of domain indicates the abstract "
                + "domain that reaches this conclusion"),
            "required": ["kind", "domain", "txtrep"],
            "properties": {
                "kind": prop_kind("unr"),
                "domain": strtype(desc="domain that signals unreachability"),
                "txtrep": txtrep()
            }
        },
        {
            "type": "object",
            "description": ("linear equality over program variables"),
            "required": ["kind", "lineq", "txtrep"],
            "properties": {
                "kind": prop_kind("lineq"),
                "lineq": refdef("linearequality"),
                "txtrep": txtrep()
            }
        }
    ]
}


locationinvariant = {
    "name": "locationinvariant",
    "title": "location invariant",
    "description": ("All invariant facts associated with a location"),
    "type": "object",
    "properties": {
        "location": strtype(
            desc=(
                "instruction hexaddress at which the assertions hold before "
                + "execution of the instruction at that address")),
        "invariants": {
            "type": "array",
            "items": refdef("invariantfact"),
            "description": "list of invariants that hold at this location"
        }
    }
}


functioninvariants = {
    "name": "functioninvariants",
    "description": ("All invariant facts associated with all locations in a function"),
    "type": "object",
    "properties": {
        "invariants": {
            "type": "array",
            "items": refdef("locationinvariant")
        }
    }
}


sectionheaderdata = {
    "name": "sectionheaderdata",
    "title": "section header data",
    "description": "name, address and size of an ELF section",
    "properties": {
        "name": strtype(desc="name of the section"),
        "vaddr": strtype(desc="virtual address of section (in hex)"),
        "size": strtype(desc="size, in bytes, of section (in memory) (in hex)")
    }
}


xcomparison = {
    "name": "xcomparison",
    "title": "binary comparison",
    "description": "Structural differences between two binaries",
    "type": "object",
    "required": ["file1", "file2"],
    "properties": {
        "file1": {
            "type": "object",
            "description": "path and filename of first file",
            "required": ["path", "filename"],
            "properties": {
                "path": strtype(),
                "filename": strtype()
            }
        },
        "file2": {
            "type": "object",
            "description": "path and filename of second file",
            "required": ["path", "filename"],
            "properties": {
                "path": strtype(),
                "filename": strtype()
            }
        },
        "newsections": {
            "type": "array",
            "description": (
                "name, address and size of sections added in patched file"),
            "items": refdef("sectionheaderdata")
        },
        "missingsections": {
            "type": "array",
            "description": "names of sections removed compared to original file",
            "items": strtype(desc="section name")
        },
        "thumb-switchpoints": {
            "type": "array",
            "description": (
                "list of thumb switchpoints addede to userdata of patched file"),
            "items": strtype(desc="switch-point (in CodeHawk form)")
        },
        "newcode": {
            "type": "array",
            "description": (
                "start and end address of newly added chunks of code in "
                + "patched file"),
            "items": {
                "type": "object",
                "description": (
                    "start and end virtual address of new code region (hex)"),
                "properties": {
                    "startaddr": strtype(),
                    "endaddr": strtype()
                }
            }
        },
        "section-differences": {
            "type": "array",
            "description": (
                "list of differences in size or starting address of existing "
                + "sections"),
            "items": {
                "type": "object",
                "description": "difference in size or virtual address",
                "properties": {
                    "name": strtype(desc="name of the section"),
                    "vaddr1": strtype(
                        desc="virtual address of section in original binary"),
                    "vaddr2": strtype(
                        desc="virtual address of section in patched binary"),
                    "size1": strtype(
                        desc="size (in hex) of section in original binary"),
                    "size2": strtype(
                        desc="size (in hex) of section in patched binary")
                }
            }
        }
    }
}