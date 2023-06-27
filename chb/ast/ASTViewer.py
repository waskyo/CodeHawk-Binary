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

import argparse
import json
import os
import subprocess
import sys

from typing import Any, cast, Dict, List, NoReturn, Optional, Tuple, TYPE_CHECKING

from chb.ast.AbstractSyntaxTree import AbstractSyntaxTree
import chb.ast.ASTNode as AST
from chb.ast.ASTNOPVisitor import ASTNOPVisitor
from chb.ast.ASTDeserializer import ASTDeserializer
import chb.ast.astdotutil as DU


nodecolors = DU.nodecolors

            
class ASTViewer(ASTNOPVisitor):

    def __init__(self, name: str, astree: AbstractSyntaxTree) -> None:
        self._astree = astree
        self._dotgraph = DU.ASTDotGraph(name)

    @property
    def astree(self) -> AbstractSyntaxTree:
        return self._astree

    @property
    def dotgraph(self) -> DU.ASTDotGraph:
        return self._dotgraph

    def add_node(
            self,
            name: str,
            labeltxt: Optional[str] = None,
            color: Optional[str] = None) -> None:
        self.dotgraph.add_node(name, labeltxt=labeltxt, color=color)

    def add_edge(
            self,
            src: str,
            tgt: str,
            labeltxt: Optional[str] = None) -> None:
        self.dotgraph.add_edge(src, tgt, labeltxt=labeltxt)

    def to_graph(self, stmt: AST.ASTStmt) -> DU.ASTDotGraph:
        stmt.accept(self)
        return self.dotgraph

    def instr_to_graph(
            self,
            instr: AST.ASTInstruction,
            provinstrs: List[AST.ASTInstruction] = []) -> DU.ASTDotGraph:
        instr.accept(self)
        for p in provinstrs:
            p.accept(self)
        return self.dotgraph

    def expr_to_graph(
            self,
            expr: AST.ASTExpr,
            provexpr: Optional[AST.ASTExpr] = None,
            rdefs: List[AST.ASTInstruction] = []) -> DU.ASTDotGraph:
        expr.accept(self)
        if provexpr is not None:
            provexpr.accept(self)
        for instr in rdefs:
            instr.accept(self)
        return self.dotgraph

    def get_expr_connections(self, expr: AST.ASTExpr) -> str:
        result: str = ""
        if self.astree.provenance.has_expression_mapping(expr.exprid):
            id = self.astree.provenance.expression_mapping[expr.exprid]
            result += "\\nmapped:" + str(id)
        if self.astree.provenance.has_reaching_definitions(expr.exprid):
            ids = self.astree.provenance.reaching_definitions[expr.exprid]
            result += "\\nrdefs:[" + ",".join(str(id) for id in ids) + "]"
        return result

    def stmt_name(self, stmt: AST.ASTStmt) -> str:
        return "stmt:" + str(stmt.stmtid)

    def visit_return_stmt(self, stmt: AST.ASTReturn) -> None:
        name = self.stmt_name(stmt)
        self.add_node(
            name, labeltxt="return:" + str(stmt.stmtid), color=nodecolors["stmt"])
        if stmt.has_return_value():
            self.add_edge(name, self.expr_name(stmt.expr))
            stmt.expr.accept(self)

    def visit_block_stmt(self, stmt: AST.ASTBlock) -> None:
        name = self.stmt_name(stmt)
        self.add_node(
            name, labeltxt="block:" + str(stmt.stmtid), color=nodecolors["stmt"])
        for s in stmt.stmts:
            if s.is_stmt_label:
                continue
            self.add_edge(name, self.stmt_name(s))
            s.accept(self)

    def visit_branch_stmt(self, stmt: AST.ASTBranch) -> None:
        name = self.stmt_name(stmt)
        self.add_node(
            name, labeltxt="if:" + str(stmt.stmtid), color=nodecolors["stmt"])
        self.add_edge(name, self.stmt_name(stmt.ifstmt), labeltxt="then")
        self.add_edge(name, self.stmt_name(stmt.elsestmt), labeltxt="else")
        self.add_edge(name, self.expr_name(stmt.condition), labeltxt="condition")
        stmt.ifstmt.accept(self)
        stmt.elsestmt.accept(self)
        stmt.condition.accept(self)

    def visit_goto_stmt(self, stmt: AST.ASTGoto) -> None:
        name = self.stmt_name(stmt)
        self.add_node(
            name, labeltxt="goto:" + stmt.destination, color=nodecolors["stmt"])

    def visit_instruction_sequence_stmt(self, stmt: AST.ASTInstrSequence) -> None:
        name = self.stmt_name(stmt)
        self.add_node(
            name, labeltxt="instrs:" + str(stmt.stmtid), color=nodecolors["stmt"])
        for instr in stmt.instructions:
            self.add_edge(name, self.instr_name(instr))
            instr.accept(self)

    def instr_span(self, instr: AST.ASTInstruction) -> str:
        locationid = instr.locationid
        if locationid in self.astree.spanmap():
            span = self.astree.spanmap()[locationid]
        else:
            span = "?"
        return "\\n" + span

    def visit_assign_instr(self, instr: AST.ASTAssign) -> None:
        name = self.instr_name(instr)
        span = self.instr_span(instr)
        self.add_node(
            name,
            labeltxt="assign:" + str(instr.instrid) + span,
            color=nodecolors["instr"])
        self.add_edge(name, self.lval_name(instr.lhs), labeltxt="lhs")
        self.add_edge(name, self.expr_name(instr.rhs), labeltxt="rhs")
        instr.lhs.accept(self)
        instr.rhs.accept(self)

    def visit_nop_instr(self, instr: AST.ASTNOPInstruction) -> None:
        name = self.instr_name(instr)
        span = self.instr_span(instr)
        self.add_node(
            name,
            labeltxt="nop:" + instr.description + ":" + str(instr.instrid) + span,
            color=nodecolors["instr"])

    def instr_name(self, instr: AST.ASTInstruction) -> str:
        return "instr:" + str(instr.instrid)

    def visit_integer_constant(self, cst: AST.ASTIntegerConstant) -> None:
        name = self.expr_name(cst)
        self.add_node(
            name,
            labeltxt="int:" + str(cst.cvalue),
            color=nodecolors["cst"])

    def visit_global_address(self, addr: AST.ASTGlobalAddressConstant) -> None:
        name = self.expr_name(addr)
        connections = self.get_expr_connections(addr)
        self.add_node(
            name,
            labeltxt="gaddr:" + hex(addr.cvalue) + ":" + str(addr.exprid) + connections,
            color=nodecolors["cst"])

    def visit_lval_expression(self, expr: AST.ASTLvalExpr) -> None:
        name = self.expr_name(expr)
        connections = self.get_expr_connections(expr)
        self.add_node(
            name,
            labeltxt="lvalexpr:" + str(expr.exprid) + connections,
            color=nodecolors["expr"])
        self.add_edge(name, self.lval_name(expr.lval))
        expr.lval.accept(self)

    def visit_unary_expression(self, expr: AST.ASTUnaryOp) -> None:
        name = self.expr_name(expr)
        self.add_node(
            name,
            labeltxt="unop:" + expr.op + ":" + str(expr.exprid),
            color=nodecolors["expr"])
        self.add_edge(name, self.expr_name(expr.exp1))
        expr.exp1.accept(self)

    def visit_binary_expression(self, expr: AST.ASTBinaryOp) -> None:
        name = self.expr_name(expr)
        connections = self.get_expr_connections(expr)
        self.add_node(
            name,
            labeltxt="binop:" + expr.op + ":" + str(expr.exprid) + connections,
            color=nodecolors["expr"])
        self.add_edge(name, self.expr_name(expr.exp1), labeltxt="exp1")
        self.add_edge(name, self.expr_name(expr.exp2), labeltxt="exp2")
        expr.exp1.accept(self)
        expr.exp2.accept(self)

    def visit_address_of_expression(self, expr: AST.ASTAddressOf) -> None:
        name = self.expr_name(expr)
        connections = self.get_expr_connections(expr)
        self.add_node(
            name,
            labeltxt="addressof:" + str(expr.exprid) + connections,
            color=nodecolors["expr"])
        self.add_edge(name, self.lval_name(expr.lval))
        expr.lval.accept(self)

    def expr_name(self, expr: AST.ASTExpr) -> str:
        if expr.is_integer_constant:
            expr = cast(AST.ASTIntegerConstant, expr)
            return "int:" + str(expr.cvalue)
        return "expr:" + str(expr.exprid)

    def visit_lval(self, lval: AST.ASTLval) -> None:
        name = self.lval_name(lval)
        self.add_node(
            name,
            labeltxt="lval:" + str(lval.lvalid),
            color=nodecolors["lval"])
        self.add_edge(name, self.lhost_name(lval.lhost))
        lval.lhost.accept(self)
        if not lval.offset.is_no_offset:
            self.add_edge(name, self.offset_name(lval.offset))
            lval.offset.accept(self)

    def lval_name(self, lval: AST.ASTLval) -> str:
        return "lval:" + str(lval.lvalid)

    def visit_variable(self, var: AST.ASTVariable) -> None:
        name = self.lhost_name(var)
        self.add_node(
            name,
            labeltxt="var:" + var.vname, color=nodecolors["var"])

    def visit_memref(self, memref: AST.ASTMemRef) -> None:
        name = self.lhost_name(memref)
        self.add_node(name, labeltxt="memref", color=nodecolors["var"])
        self.add_edge(name, self.expr_name(memref.memexp))
        memref.memexp.accept(self)

    def lhost_name(self, lhost: AST.ASTLHost) -> str:
        if lhost.is_variable:
            lhost = cast(AST.ASTVariable, lhost)
            return "lhost:var:" + lhost.vname
        elif lhost.is_memref:
            lhost = cast(AST.ASTMemRef, lhost)
            return "lhost:memref:" + str(lhost.memexp.exprid)
        else:
            return "lhost:?"

    def visit_index_offset(self, offset: AST.ASTIndexOffset) -> None:
        name = self.offset_name(offset)
        self.add_node(
            name, labeltxt="indexoffset", color=nodecolors["lval"])
        self.add_edge(name, self.expr_name(offset.index_expr))
        offset.index_expr.accept(self)
        if not offset.offset.is_no_offset:
            self.add_edge(name, self.offset_name(offset.offset))
            offset.offset.accept(self)

    def offset_name(self, offset: AST.ASTOffset) -> str:
        if offset.is_no_offset:
            return "no-offset"
        elif offset.is_field_offset:
            offset = cast(AST.ASTFieldOffset, offset)
            return "field:" + offset.fieldname + ":" + str(offset.compkey)
        else:
            offset = cast(AST.ASTIndexOffset, offset)
            return "index:" + str(offset.index_expr.exprid)