# Ask GPT
# @author Emi Bemol <emi@pokemod.dev>
# @category machineLearning
# @version 1.0
# @toolbar wizard.png

from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.pcode import HighFunctionDBUtil

import logging
from pprint import pprint

from GhidraCopilot.utils import is_auto_generated, get_current_function
from GhidraCopilot.renamers.function_arguments import (
    generate_argument_renames, rename_arguments)
from GhidraCopilot.renamers.function_calls import (
    find_functions_to_rename, generate_function_renames, rename_functions)
from GhidraCopilot.renamers.global_variables import (
    find_globals_to_rename, generate_global_renames, rename_globals)
from GhidraCopilot.renamers.labels import (find_labels_to_rename,
                                     generate_label_renames, rename_labels)
from GhidraCopilot.renamers.local_variables import (
    generate_local_variable_renames, rename_local_variables,
    split_local_variables)
from __main__ import currentProgram, currentAddress, askChoices

logging.basicConfig(level=logging.INFO)
options = DecompileOptions()
monitor = ConsoleTaskMonitor()
interface = DecompInterface()
interface.setOptions(options)
interface.openProgram(currentProgram)

func = get_current_function(address=currentAddress, program=currentProgram)
decompiled = interface.decompileFunction(func, 10, monitor)

# --- Get initial list of auto-generated local vars to split them ---
high_func_initial = decompiled.getHighFunction()
lsm_initial = high_func_initial.getLocalSymbolMap()
symbols_initial = lsm_initial.getSymbols()
local_vars_to_split = list(set([s.getName() for s in symbols_initial if not s.isParameter() and is_auto_generated(s.getName())]))

if local_vars_to_split:
    split_local_variables(decompiled, local_vars_to_split)

    # Re-decompile to get the updated code and symbol map
    logging.info("Re-decompiling function to reflect split variables...")
    decompiled = interface.decompileFunction(func, 10, monitor)

# Now, get the fresh data from the new decompilation
code = decompiled.getDecompiledFunction().getC()
high_func = decompiled.getHighFunction()
lsm = high_func.getLocalSymbolMap()
symbols = lsm.getSymbols()

# --- Identify all auto-generated symbols (using the new, split names) ---
local_vars = list(set([s.getName() for s in symbols if not s.isParameter() and is_auto_generated(s.getName())]))
arguments = list(set([s.getName() for s in symbols if s.isParameter() and is_auto_generated(s.getName())]))
globals_found = find_globals_to_rename(code)
functions_found = find_functions_to_rename(code)
labels_found = find_labels_to_rename(code)

# --- Ask user what to rename ---
choices = []
if local_vars: choices.append("Local Variables ({})".format(len(local_vars)))
if arguments: choices.append("Arguments ({})".format(len(arguments)))
if globals_found: choices.append("Globals ({})".format(len(globals_found)))
if functions_found: choices.append("Functions ({})".format(len(functions_found)))
if labels_found: choices.append("Labels ({})".format(len(labels_found)))

if not choices:
    logging.info("No auto-generated symbols found to rename.")
    exit()

selected_choices = askChoices("Symbol Types to Rename", "Select which types of symbols you want to rename:", choices)

# --- Process each selected type ---
for choice in selected_choices:
    if choice.startswith("Local Variables"):
        logging.info("Requesting renames for local variables: {}".format(local_vars))
        renames = generate_local_variable_renames(code, local_vars)
        if renames:
            rename_local_variables(decompiled, renames)

    if choice.startswith("Arguments"):
        logging.info("Requesting renames for arguments: {}".format(arguments))
        renames = generate_argument_renames(code, arguments)
        if renames:
            rename_arguments(decompiled, renames)

    if choice.startswith("Globals"):
        logging.info("Requesting renames for globals: {}".format(globals_found))
        renames = generate_global_renames(func, interface, globals_found)
        if renames:
            rename_globals(renames)

    if choice.startswith("Functions"):
        logging.info("Requesting renames for functions: {}".format(functions_found))
        renames = generate_function_renames(interface, code, functions_found)
        if renames:
            rename_functions(renames)

    if choice.startswith("Labels"):
        logging.info("Requesting renames for labels: {}".format(labels_found))
        renames = generate_label_renames(code, labels_found)
        if renames:
            rename_labels(renames)

logging.info("Finished renaming process.")
