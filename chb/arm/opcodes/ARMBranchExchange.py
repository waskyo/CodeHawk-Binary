# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2025 Aarno Labs LLC
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

from typing import List, Optional, Sequence, Tuple, TYPE_CHECKING

from chb.app.InstrXData import InstrXData

from chb.arm.ARMCallOpcode import ARMCallOpcode
from chb.arm.ARMDictionaryRecord import armregistry
from chb.arm.ARMOpcode import ARMOpcode, ARMOpcodeXData, simplify_result
from chb.arm.ARMOperand import ARMOperand

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

from chb.invariants.XXpr import XXpr


import chb.util.fileutil as UF
from chb.util.loggingutil import chklogger
from chb.util.IndexedTable import IndexedTableValue
from chb.util.loggingutil import chklogger


if TYPE_CHECKING:
    from chb.api.CallTarget import CallTarget, AppTarget, StaticStubTarget
    from chb.arm.ARMDictionary import ARMDictionary
    from chb.invariants.XVariable import XVariable
    from chb.invariants.XXpr import XXpr


class ARMBranchExchangeXData(ARMOpcodeXData):

    def __init__(self, xdata: InstrXData) -> None:
        ARMOpcodeXData.__init__(self, xdata)

    @property
    def xtgt(self) -> "XXpr":
        return self.xpr(0, "xtgt")

    @property
    def xxtgt(self) -> "XXpr":
        return self.xpr(1, "xxtgt")

    def has_return_xpr(self) -> bool:
        return self.xdata.has_return_xpr()

    def returnval(self) -> "XXpr":
        return self.xdata.get_return_xpr()

    def rreturnval(self) -> "XXpr":
        return self.xdata.get_return_xxpr()

    @property
    def annotation(self) -> str:
        if self.has_return_xpr():
            return "return " + str(self.rreturnval())
        else:
            return "Not supported yet"


@armregistry.register_tag("BX", ARMOpcode)
class ARMBranchExchange(ARMCallOpcode):
    """Branch to an address and instruction set specified by a register.

    tags[1]: <c>
    args[0]: index of target operand in armdictionary
    """

    def __init__(self, d: "ARMDictionary", ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 1, "BranchExchange")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[0])]

    def ft_conditions(self, xdata: InstrXData) -> Sequence[XXpr]:
        if xdata.has_branch_conditions():
            return [xdata.xprs[1], xdata.xprs[0]]
        else:
            return []

    def is_return_instruction(self, xdata: InstrXData) -> bool:
        tgtop = self.operands[0]
        if tgtop.is_register:
            return tgtop.register == "LR"
        else:
            return False

    def return_value(self, xdata: InstrXData) -> Optional[XXpr]:
        xd = ARMBranchExchangeXData(xdata)
        if xd.has_return_xpr():
            return xd.rreturnval()
        else:
            return None

    def is_call(self, xdata: InstrXData) -> bool:
        return len(xdata.tags) >= 2 and xdata.tags[1] == "call"

    def is_call_instruction(self, xdata: InstrXData) -> bool:
        # return xdata.has_call_target()
        return False

    def call_target(self, xdata: InstrXData) -> "CallTarget":
        if self.is_call_instruction(xdata):
            return xdata.call_target(self.ixd)
        else:
            raise UF.CHBError("Instruction is not a call: " + str(self))

    def argument_count(self, xdata: InstrXData) -> int:
        if self.is_call_instruction(xdata):
            argcount = xdata.call_target_argument_count()
            if argcount is not None:
                return argcount
            chklogger.logger.warning(
                "Call instruction does not have argument count")
            return 0
        else:
            raise UF.CHBError("Instruction is not a call: " + str(self))

    def arguments(self, xdata: InstrXData) -> Sequence[XXpr]:
        return xdata.xprs[:self.argument_count(xdata)]

    def annotation(self, xdata: InstrXData) -> str:
        """xdata format: a:x .

        xprs[0]: target operand
        """
        if self.is_call_instruction(xdata):
            tgt = xdata.call_target(self.ixd)
            args = ", ".join(str(x) for x in self.arguments(xdata))
            return "call " + str(tgt) + "(" + args + ")"

        xd = ARMBranchExchangeXData(xdata)
        if xd.has_return_xpr and xd.is_ok:
            return xd.annotation
        elif xd.is_ok:
            return "goto " + str(xd.xxtgt)
        else:
            return "Error value"

    def assembly_ast(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> List[AST.ASTInstruction]:
        """Need check for branch on LR, which should emit a return statement."""
        return []

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        annotations: List[str] = [iaddr, "BX"]

        if self.is_call_instruction(xdata) and xdata.has_call_target():
            return self.ast_call_prov(
                astree, iaddr, bytestring, "BranchExchange", xdata)
        else:
            nopinstr = astree.mk_nop_instruction(
                "BX", iaddr=iaddr, bytestring=bytestring, annotations=annotations)
            astree.add_instr_address(nopinstr, [iaddr])

            return ([], [nopinstr])

    def ast_call_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            name: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        return ARMCallOpcode.ast_call_prov(
            self, astree, iaddr, bytestring, "BranchExchange (BX)", xdata)
