# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2025  Aarno Labs LLC
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

from typing import List, Tuple, TYPE_CHECKING

from chb.app.InstrXData import InstrXData

from chb.arm.ARMDictionaryRecord import armregistry
from chb.arm.ARMOpcode import ARMOpcode, ARMOpcodeXData, simplify_result
from chb.arm.ARMOperand import ARMOperand

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF
from chb.util.IndexedTable import IndexedTableValue
from chb.util.loggingutil import chklogger

if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary
    from chb.invariants.XVariable import XVariable
    from chb.invariants.XXpr import XXpr


class ARMLoadMultipleIncrementAfterXData(ARMOpcodeXData):

    def __init__(self, xdata: InstrXData) -> None:
        ARMOpcodeXData.__init__(self, xdata)

    @property
    def regcount(self) -> int:
        return len(self.xdata.vars_r) - 1

    @property
    def baselhs(self) -> "XVariable":
        return self.var(0, "baselhs")

    @property
    def lhsvars(self) -> List["XVariable"]:
        return [self.var(i, "lhsvar") for i in range(1, self.regcount + 1)]

    @property
    def baserhs(self) -> "XXpr":
        return self.xpr(0, "baserhs")

    @property
    def rhsexprs(self) -> List["XXpr"]:
        return [self.xpr(i, "rhsexpr") for i in range(1, self.regcount + 1)]

    @property
    def xaddrs(self) -> List["XXpr"]:
        return [self.xpr(i, "xaddr")
                for i in range(self.regcount + 1, (2 * self.regcount) + 3)]

    @property
    def annotation(self) -> str:
        pairs = zip(self.lhsvars, self.rhsexprs)
        assigns = "; ".join(str(v) + " := " + str(x) for (x, v) in pairs)
        wbu = self.writeback_update()
        return self.add_instruction_condition(assigns + wbu)


@armregistry.register_tag("LDM", ARMOpcode)
class ARMLoadMultipleIncrementAfter(ARMOpcode):
    """Loads multiple registers from consecutive memory locations.

    LDM<c> <Rn>, <registers>

    tags[1]: <c>
    args[0]: writeback
    args[1]: index of Rn in arm dictionary
    args[2]: index of registers in arm dictionary
    args[3]: index of base memory address

    xdata format: vv[n]xxxx[n]rr[n]dd[n]hh[n]
    ----------------------------------------
    vars[0]: base lhs
    vars[1..n]: register lhss
    xprs[0]: base rhs
    xprs[1]: updated base (may be unchanged in case of no writeback)
    xprs[2]: updated base (simplified)
    xprs[3..n+2]: values of memory locations read
    rdefs[0]: reaching definition base register
    rdefs[1..n]: reaching definition memory locations
    uses[0]: base lhs
    uses[1..n]: register lhss
    useshigh[0]: base lhs
    useshigh[1..n]: register lhss
    """

    def __init__(self, d: "ARMDictionary", ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 4, "LoadMultipleIncrementAfter")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(i) for i in self.args[1:]]

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(i) for i in self.args[1:]]

    @property
    def operandstring(self) -> str:
        return (
            str(self.armd.arm_operand(self.args[1]))
            + ("!" if self.args[0] == 1 else "")
            + ", "
            + str(self.armd.arm_operand(self.args[2])))

    @property
    def writeback(self) -> bool:
        return self.args[0] == 1

    def is_load_instruction(self, xdata: InstrXData) -> bool:
        return True

    def annotation(self, xdata: InstrXData) -> str:
        xd = ARMLoadMultipleIncrementAfterXData(xdata)
        if xd.is_ok:
            return xd.annotation
        else:
            return "Error value"

    # -------------------------------------------------------------------------
    # address = R[n];
    # for i = 0 to 14
    #   if registers<i> == '1' then
    #     R[i] = MemA[address, 4];
    #     address = address + 4;
    # if registers<15> == '1' then
    #   loadWritePC(MemA[address, 4]);
    # if wback && registers<n> == '0' then
    #   R[n] = R[n] + 4 * BitCount(registers);
    # -------------------------------------------------------------------------
    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        xd = ARMLoadMultipleIncrementAfterXData(xdata)
        if not xd.is_ok:
            chklogger.logger.error(
                "Error value encountered at address %s", iaddr)
            return ([], [])

        baselhs = xd.baselhs
        lhsvars = xd.lhsvars
        baserhs = xd.baserhs
        rhsexprs = xd.rhsexprs

        baserdef = xdata.reachingdefs[0]
        memrdefs = xdata.reachingdefs[1:]
        baseuses = xdata.defuses[0]
        reguses = xdata.defuses[1:]
        baseuseshigh = xdata.defuseshigh[0]
        reguseshigh = xdata.defuseshigh[1:]

        annotations: List[str] = [iaddr, "LDMIA"]

        ll_instrs: List[AST.ASTInstruction] = []
        hl_instrs: List[AST.ASTInstruction] = []

        # low-level assignments

        (baselval, _, _) = self.opargs[0].ast_lvalue(astree)
        (baserval, _, _) = self.opargs[0].ast_rvalue(astree)

        regsop = self.opargs[1]
        registers = regsop.registers
        base_offset = 0
        for (i, r) in enumerate(registers):

            # low-level assignments

            base_offset_c = astree.mk_integer_constant(base_offset)
            addr = astree.mk_binary_op("plus", baserval, base_offset_c)
            ll_lhs = astree.mk_variable_lval(r)
            ll_rhs = astree.mk_memref_expr(addr)
            ll_assign = astree.mk_assign(
                ll_lhs,
                ll_rhs,
                iaddr=iaddr,
                bytestring=bytestring,
                annotations=annotations)
            ll_instrs.append(ll_assign)

            # high-level assignments

            lhs = lhsvars[i]
            rhs = rhsexprs[i]
            hl_lhs = XU.xvariable_to_ast_lval(lhs, xdata, iaddr, astree)
            hl_rhs = XU.xxpr_to_ast_def_expr(rhs, xdata, iaddr, astree)
            hl_assign = astree.mk_assign(
                hl_lhs,
                hl_rhs,
                iaddr=iaddr,
                bytestring=bytestring,
                annotations=annotations)
            hl_instrs.append(hl_assign)

            astree.add_instr_mapping(hl_assign, ll_assign)
            astree.add_instr_address(hl_assign, [iaddr])
            astree.add_expr_mapping(hl_rhs, ll_rhs)
            astree.add_lval_mapping(hl_lhs, ll_lhs)
            astree.add_expr_reachingdefs(ll_rhs, [memrdefs[i]])
            astree.add_lval_defuses(hl_lhs, reguses[i])
            astree.add_lval_defuses_high(hl_lhs, reguseshigh[i])

            base_offset += 4

        if self.writeback:

            # low-level base assignment

            baseincr = 4 * xd.regcount
            baseincr_c = astree.mk_integer_constant(baseincr)

            ll_base_lhs = baselval
            ll_base_rhs = astree.mk_binary_op("plus", baserval, baseincr_c)
            ll_base_assign = astree.mk_assign(
                ll_base_lhs,
                ll_base_rhs,
                iaddr=iaddr,
                bytestring=bytestring,
                annotations=annotations)
            ll_instrs.append(ll_base_assign)

            # high-level base assignment

            baseresult = xd.get_base_update_xpr()
            hl_base_lhs = XU.xvariable_to_ast_lval(baselhs, xdata, iaddr, astree)
            hl_base_rhs = XU.xxpr_to_ast_def_expr(
                baseresult, xdata, iaddr, astree)
            hl_base_assign = astree.mk_assign(
                hl_base_lhs,
                hl_base_rhs,
                iaddr=iaddr,
                bytestring=bytestring,
                annotations=annotations)
            hl_instrs.append(hl_base_assign)

            astree.add_instr_mapping(hl_base_assign, ll_base_assign)
            astree.add_instr_address(hl_base_assign, [iaddr])
            astree.add_expr_mapping(hl_base_rhs, ll_base_rhs)
            astree.add_lval_mapping(hl_base_lhs, ll_base_lhs)
            astree.add_expr_reachingdefs(ll_base_rhs, [baserdef])
            astree.add_lval_defuses(hl_base_lhs, baseuses)
            astree.add_lval_defuses_high(hl_base_lhs, baseuseshigh)

        return (hl_instrs, ll_instrs)
