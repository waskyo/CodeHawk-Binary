# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2024  Aarno Labs LLC
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

from typing import cast, List, Tuple, TYPE_CHECKING

from chb.app.InstrXData import InstrXData

from chb.arm.ARMDictionaryRecord import armregistry
from chb.arm.ARMOpcode import ARMOpcode, simplify_result
from chb.arm.ARMOperand import ARMOperand

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF
from chb.util.IndexedTable import IndexedTableValue
from chb.util.loggingutil import chklogger


if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary


@armregistry.register_tag("UBFX", ARMOpcode)
class ARMUnsignedExtractBitField(ARMOpcode):
    """Extracts any number of adjacent bits from a register, zero-extends them.

    UBFX<c> <Rd>, <Rn>, #<lsb>, #<width>

    tags[1]: <c>
    args[0]: index of Rd in armdictionary
    args[1]: index of Rn in armdictionary

    xdata format: a:vxxrdh
    ----------------------
    vars[0]: lhs (Rd)
    xprs[0]: xrn (Rn)
    xprs[1]: xrn (simplified)
    rdefs[0]: Rn
    uses[0]: lhs
    useshigh: lhs
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 2, "UnsignedBitFieldExtract")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(i) for i in self.args]

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(i) for i in self.args]

    def annotation(self, xdata: InstrXData) -> str:
        """xdata format: a:vxx .

        vars[0]: lhs
        xprs[0]: rhs1
        xprs[1]: value to be stored (syntactic)
        """

        lhs = str(xdata.vars[0])
        result = xdata.xprs[0]
        rresult = xdata.xprs[1]
        xresult = simplify_result(xdata.args[1], xdata.args[2], result, rresult)
        return lhs + " := " + xresult

    # --------------------------------------------------------------------------
    # Operation
    #  msbit = lsbit = widthminus1
    #  R[d] = ZeroExtend(R[n]<msbit:lsbit>, 32);
    # --------------------------------------------------------------------------
    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        annotations: List[str] = [iaddr, "UBFX"]

        lhs = xdata.vars[0]
        rhs = xdata.xprs[1]
        rdefs = xdata.reachingdefs
        defuses = xdata.defuses
        defuseshigh = xdata.defuseshigh

        (ll_rhs, _, _) = self.opargs[1].ast_rvalue(astree)
        (ll_lhs, _, _) = self.opargs[0].ast_lvalue(astree)

        hl_lhss = XU.xvariable_to_ast_lvals(lhs, xdata, astree)

        try:
            hl_rhss = XU.xxpr_to_ast_def_exprs(rhs, xdata, iaddr, astree)
        except UF.CHBError as e:
            chklogger.logger.error(
                "Error in UBFX at address %s: %s", iaddr, str(e))
            hl_rhss = [ll_rhs]

        if len(hl_rhss) == 1 and len(hl_lhss) == 1:
            hl_lhs = hl_lhss[0]
            hl_rhs = hl_rhss[0]

            return self.ast_variable_intro(
                astree,
                astree.astree.unsigned_char_type,
                hl_lhs,
                hl_rhs,
                ll_lhs,
                ll_rhs,
                rdefs[1:],
                [rdefs[0]],
                defuses[0],
                defuseshigh[0],
                True,
                iaddr,
                annotations,
                bytestring)

        else:
            raise UF.CHBError(
                "ARMUnsignedBitFieldExtract: multiple expressions/lvals in ast")
