# extract_integrated_nodotenv.py  (Jython for Ghidra headless)
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import codecs
import sys
import os

args = getScriptArgs()
if args is None or len(args) < 2:
    exit(0)

out_dir = args[0]
out_name = args[1]
if not out_name.endswith(".txt"):
    out_name += ".txt"

program = currentProgram
if program is None:
    exit(0)

if not os.path.isdir(out_dir):
    os.makedirs(out_dir)

out_path = os.path.join(out_dir, out_name)

decomp = DecompInterface()
decomp.openProgram(program)
monitor = ConsoleTaskMonitor()

with codecs.open(out_path, "w", "utf-8") as f:
    f.write(u"[*] Binary Name: {}\n\n".format(program.getName()))

    fm = program.getFunctionManager()
    refMgr = program.getReferenceManager()
    functions = fm.getFunctions(True)

    for func in list(functions):
        f.write(u"[*] Function Found: {}\n".format(func))
        f.write(u"    Address: {}\n".format(func.getEntryPoint()))

        try:
            res = decomp.decompileFunction(func, 0, monitor)
            if not res.decompileCompleted():
                f.write(u"    Failed to decompile function\n\n")
                continue

            cfunc = res.getDecompiledFunction()
            ccode = cfunc.getC() if cfunc is not None else ""
            if ccode is None:
                ccode = ""

            f.write(u"    Decompiled C Code:\n{}\n".format(ccode))

            # Parameters
            try:
                for p in func.getParameters():
                    f.write(u"    Parameter: {} : {}\n".format(p.getName(), p.getDataType()))
            except:
                pass

            # Locals
            try:
                for v in func.getLocalVariables():
                    f.write(u"    Local Variable: {} : {}\n".format(v.getName(), v.getDataType()))
            except:
                pass

            # Called by (callers)
            try:
                refs = refMgr.getReferencesTo(func.getEntryPoint())
                for r in refs:
                    try:
                        if r.getReferenceType().isCall():
                            caller = fm.getFunctionContaining(r.getFromAddress())
                            if caller:
                                f.write(u"    Called by: {}\n".format(caller.getName()))
                    except:
                        continue
            except:
                pass

        except Exception as e:
            f.write(u"    Exception occurred: {}\n\n".format(e))

        f.write(u"\n")
