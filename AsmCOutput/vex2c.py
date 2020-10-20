import pyvex


def get_C_type(type):
    map = {
        "Ity_F32": "float",
        "Ity_F64": "double",
        "Ity_I1": "uint8_t",
        "Ity_I8": "uint8_t",
        "Ity_I16": "uint16_t",
        "Ity_I32": "uint32_t",
        "Ity_I64": "uint64_t",
    }

    return map[type]

def exp_to_C(expr: pyvex.expr.IRExpr, arch, tyenv, file):
    assert isinstance(expr, pyvex.expr.IRExpr)

    if isinstance(expr, pyvex.expr.Binop):
        arg1, arg2 = expr.args

        # careful about types with these --
        # in particular, make no assumptions about the operands being signed/unsigned
        simple_binary_operators = {
            "Iop_Add32": "+",
            "Iop_And8": "&",
            "Iop_And32": "&",
            "Iop_CmpEQ8": "==",
            "Iop_CmpEQ16": "==",
            "Iop_CmpEQ32": "==",
            "Iop_CmpLE32S": ("<=", "int32_t", "int32_t"),
            "Iop_CmpLT32S": ("<", "int32_t", "int32_t"),
            "Iop_Shl32": "<<",
            "Iop_Sub8": "-",
            "Iop_Sub32": "-",
        }

        pattern_ops = {
            "Iop_And16":        "($1 & $2)",
            "Iop_CmpNE8":       "($1 != $2)",
            "Iop_CmpNE32":      "($1 != $2)",
            "Iop_CmpLE32U":     "(((int32_t) $1) <= ((int32_t) $2))",
            "Iop_CmpLT32U":     "(((int32_t) $1) < ((int32_t) $2))",
            "Iop_Mul32":        "(((int32_t) $1) * ((int32_t) $2))",    # apparently signed (generated for x86 IMUL)
            "Iop_Or8":          "($1 | $2)",
            "Iop_Or16":         "($1 | $2)",
            "Iop_Or32":         "($1 | $2)",
            "Iop_Sar32":        "(((int32_t) $1) >> $2)",
            "Iop_Shr32":        "(((uint32_t) $1) >> $2)",
            "Iop_Xor32":        "($1 ^ $2)",
        }

        if expr.op in simple_binary_operators:
            op = simple_binary_operators[expr.op]

            if isinstance(op, tuple):
                op, cast1, cast2 = op
                file.write(f"((({cast1}) ")
                exp_to_C(arg1, arch=arch, tyenv=tyenv, file=file)
                file.write(f") {op} (({cast2}) ")
                exp_to_C(arg2, arch=arch, tyenv=tyenv, file=file)
                file.write("))")
            else:
                file.write(f"(")
                exp_to_C(arg1, arch=arch, tyenv=tyenv, file=file)
                file.write(f" {op} ")
                exp_to_C(arg2, arch=arch, tyenv=tyenv, file=file)
                file.write(")")
        elif expr.op in pattern_ops:
            part1, part23 = pattern_ops[expr.op].split("$1")
            part2, part3 = part23.split("$2")

            file.write(part1)
            exp_to_C(arg1, arch=arch, tyenv=tyenv, file=file)
            file.write(part2)
            exp_to_C(arg2, arch=arch, tyenv=tyenv, file=file)
            file.write(part3)
        else:
            file.write(f"{expr.op}(")
            exp_to_C(arg1, arch=arch, tyenv=tyenv, file=file)
            file.write(", ")
            exp_to_C(arg2, arch=arch, tyenv=tyenv, file=file)
            file.write(")")
    elif isinstance(expr, pyvex.expr.Const):
        # file.write(f"/* Const: {type(expr.con)} {expr.con.value} {expr.result_type(tyenv)} */ ")
        if expr.con.value != expr.con.value:
            # NaN
            # file.write(f"{expr.result_type(tyenv)}_nan()")
            file.write("NAN")
        else:
            file.write(f"{expr.con}")
    elif isinstance(expr, pyvex.expr.CCall):
        file.write(f"{expr.cee}(")
        for i, arg in enumerate(expr.args):
            if i > 0: file.write(", ")
            exp_to_C(arg, arch=arch, tyenv=tyenv, file=file)
        file.write(")")

        # raise Exception(f"Unhandled {expr} ({expr.retty}, {expr.cee}, {expr.args})")
    elif isinstance(expr, pyvex.expr.Get):
        reg_name = arch.translate_register_name(expr.offset, expr.result_size(tyenv) // 8)

        file.write(f"cpu.{reg_name}")
    elif isinstance(expr, pyvex.expr.GetI):
        file.write("(AsmCrt_not_implemented(GetI), 0)")
    elif isinstance(expr, pyvex.expr.ITE):
        file.write("(")
        exp_to_C(expr.cond, arch=arch, tyenv=tyenv, file=file)
        file.write(") ? (")
        exp_to_C(expr.iftrue, arch=arch, tyenv=tyenv, file=file)
        file.write(") : (")
        exp_to_C(expr.iffalse, arch=arch, tyenv=tyenv, file=file)
        file.write(")")
    elif isinstance(expr, pyvex.expr.Load):
        assert expr.end == "Iend_LE"

        size = expr.result_size(tyenv)
        file.write(f"Load_{size}(")
        exp_to_C(expr.addr, arch=arch, tyenv=tyenv, file=file)
        file.write(")")
    elif isinstance(expr, pyvex.expr.RdTmp):
        file.write(f"t{expr.tmp}")
    elif isinstance(expr, pyvex.expr.Unop):
        arg1, = expr.args

        no_ops = {  # widening casts, mainly
            "Iop_1Uto8",
            "Iop_1Uto32",
            "Iop_16Uto32",
            "Iop_F32toF64",
        }

        pattern_ops = {
            "Iop_8Sto32": "((int32_t)(int8_t) $1)",
            "Iop_8Uto32": "((uint32_t)(uint8_t) $1)",
            "Iop_16to8": "((uint8_t) $1)",
            "Iop_16HIto8": "((uint8_t) ($1 >> 8))",
            "Iop_32to1": "(!! $1)",
            "Iop_32to8": "((uint8_t) $1)",
            "Iop_32to16": "((uint16_t) $1)",
            "Iop_64to32":           "((uint32_t) $1)",
            "Iop_64HIto32":         "((uint32_t) ($1 >> 32))",
            "Iop_Not32":            "(~ $1)",
        }

        if expr.op in no_ops:
            exp_to_C(arg1, arch=arch, tyenv=tyenv, file=file)
        elif expr.op in pattern_ops:
            part1, part2 = pattern_ops[expr.op].split("$1")
            file.write(part1)
            exp_to_C(arg1, arch=arch, tyenv=tyenv, file=file)
            file.write(part2)
        else:
            # file.write(f"{expr.op}(")
            # exp_to_C(arg1, arch=arch, tyenv=tyenv, file=file)
            # file.write(")")
            raise Exception(expr.op)
    else:
        raise Exception(f"Unhandled {type(expr)} {expr}")


def irsb_to_C(irsb: pyvex.block.IRSB, file):
    arch = irsb.arch
    tyenv = irsb.tyenv

    for statement in irsb.statements:
        print(f"    // {statement}", file=file)

        if isinstance(statement, pyvex.stmt.IMark):
            continue

        file.write("    ")

        if isinstance(statement, pyvex.stmt.Exit):
            file.write(f"if (")
            exp_to_C(statement.guard, arch=arch, tyenv=tyenv, file=file)
            file.write(") { ")

            if statement.jk in {"Ijk_EmWarn", "Ijk_MapFail", "Ijk_SigFPE_IntDiv"}:
                file.write(f"AsmCrt_not_implemented({statement.jk});")
            else:
                assert statement.jk == "Ijk_Boring"

                reg_name = arch.translate_register_name(statement.offsIP, statement.dst.size // 8)
                # assert reg_name == "eip"

                # file.write(f"cpu.next_block = ")
                file.write(f"cpu.{reg_name} = ")

                file.write(f"0x{statement.dst.value:08X}; ")

                file.write("return;")

            file.write(" }\n")
        elif isinstance(statement, pyvex.stmt.Put):
            reg_name = arch.translate_register_name(statement.offset, statement.data.result_size(tyenv) // 8)

            file.write(f"cpu.{reg_name} = ")
            exp_to_C(statement.data, arch=arch, tyenv=tyenv, file=file)
            file.write(";\n")
        elif isinstance(statement, pyvex.stmt.PutI):
            file.write('AsmCrt_not_implemented(PutI);\n')
        elif isinstance(statement, pyvex.stmt.Store):
            assert statement.end == "Iend_LE"

            size = statement.data.result_size(tyenv)
            file.write(f"Store_{size}(")
            exp_to_C(statement.addr, arch=arch, tyenv=tyenv, file=file)
            file.write(", ")
            exp_to_C(statement.data, arch=arch, tyenv=tyenv, file=file)
            file.write(");\n")
        elif isinstance(statement, pyvex.stmt.WrTmp):
            native_type = get_C_type(statement.data.result_type(tyenv))
            file.write(f"{native_type} t{statement.tmp} = ")

            exp_to_C(statement.data, arch=arch, tyenv=tyenv, file=file)
            file.write(";\n")
        else:
            raise Exception(f"Unhandled {type(statement)}")

    reg_name = arch.translate_register_name(irsb.offsIP, irsb.next.result_size(tyenv) // 8)
    assert reg_name == "eip"
    assert irsb.jumpkind in {"Ijk_Boring", "Ijk_Call", "Ijk_Ret"}

    # file.write("    cpu.next_block = ")
    file.write(f"    cpu.{reg_name} = ")
    exp_to_C(irsb.next, arch=arch, tyenv=tyenv, file=file)
    file.write(";\n")
