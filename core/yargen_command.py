# -*- coding: utf-8 -*-
import sys

def append_arg(cmd, flag, value):
    if value:
        cmd.extend([flag, value])

def build_generate_command(state):
    cmd = [state.var_python.get().strip() or sys.executable, "-W", "ignore", state.var_yargen.get().strip()]
    cmd += ["-m", state.var_malware.get().strip()]
    cmd += ["-o", state.var_output.get().strip()]

    append_arg(cmd, "-e", state.var_string_export_dir.get().strip() if state.var_strings.get() else "")
    append_arg(cmd, "-a", state.var_author.get().strip())
    append_arg(cmd, "-r", state.var_reference.get().strip())
    append_arg(cmd, "-l", state.var_license.get().strip())
    append_arg(cmd, "-p", state.var_prefix.get().strip())
    append_arg(cmd, "-b", state.var_identifier_file.get().strip())

    for flag, value in [
        ("-y", state.var_min_len.get()), ("-z", state.var_min_score.get()),
        ("-x", state.var_high_score.get()), ("-w", state.var_super_min.get()),
        ("-s", state.var_max_len.get()), ("-rc", state.var_rule_count.get()),
        ("-fs", state.var_file_size.get()), ("-fm", state.var_filesize_multiplier.get()),
        ("-n", state.var_opcode_num.get()),
    ]:
        append_arg(cmd, flag, value.strip())

    for flag, var in [
        ("--score", state.var_score), ("--strings", state.var_strings), ("--excludegood", state.var_excludegood),
        ("--nosimple", state.var_nosimple), ("--nomagic", state.var_nomagic), ("--nofilesize", state.var_nofilesize),
        ("--globalrule", state.var_globalrule), ("--nosuper", state.var_nosuper), ("--dropzone", state.var_dropzone),
        ("--nr", state.var_nr), ("--oe", state.var_oe), ("--noextras", state.var_noextras), ("--ai", state.var_ai),
        ("--debug", state.var_debug), ("--trace", state.var_trace), ("--opcodes", state.var_opcodes),
        ("--inverse", state.var_inverse), ("--nodirname", state.var_nodirname), ("--noscorefilter", state.var_noscorefilter),
    ]:
        if var.get():
            cmd.append(flag)
    return cmd
