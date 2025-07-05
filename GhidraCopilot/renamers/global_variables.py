# -*- coding: utf-8 -*-
import logging
import re
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.symbol import SourceType
from __main__ import currentProgram

from ghidra.util.task import ConsoleTaskMonitor

from ..llm import build_prompt, send_prompt_to_llm

# --- SCHEMA ---
SCHEMA_GLOBALS = {
    "type": "object",
    "properties": {
        "global_renames": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "old_name": {"type": "string", "description": "The original, auto-generated name of the global variable."},
                    "new_name": {"type": "string", "description": "The new, semantically meaningful name for the global variable."},
                },
                "required": ["old_name", "new_name"],
            },
            "description": "A list of proposed global variable renames.",
        }
    },
    "required": ["global_renames"],
}

# --- PROMPT ---
EXAMPLE_CODE_1 = """
/* Void Initialize(NianticAuthPlugin+InitContext) */

void NianticAuthPlugin_Initialize(NianticAuthPlugin_InitContext *context,MethodInfo *method)

{
  byte bVar1;
  MethodInfo *method_00;
  MethodInfo *extraout_r1;
  MethodInfo *method_01;
  String *pSVar2;
  Action_2_Niantic_Platform_Ditto_Plugin_LogLevel_String_ *value;

  if (DAT_04b65fce == '\\0') {
    FUN_00dfeb14(0xb156);
    DAT_04b65fce = '\\x01';
  }
  if (context == (NianticAuthPlugin_InitContext *)0x0) {
    NullErrorException();
  }
  value = context->LogHandler;
  bVar1 = (LogApi_1__TypeInfo->_1).field_0x5b;
  method_00 = (MethodInfo *)(uint)bVar1;
  if (((bVar1 & 2) != 0) &&
     (method_00 = (MethodInfo *)(LogApi_1__TypeInfo->_1).cctor_finished,
     method_00 == (MethodInfo *)0x0)) {
    FUN_00e0da3c((int)LogApi_1__TypeInfo);
    method_00 = extraout_r1;
  }
  LogApi_1_set_LogHandler(value,method_00);
  LogApi_1_set_LogLevel(context->DefaultLogLevel,method_01);
  pSVar2 = context->DesktopRcPath;
  if (DAT_04b65fcd == '\\0') {
    FUN_00dfeb14(0xb158);
    DAT_04b65fcd = '\\x01';
  }
  NianticAuthPlugin__TypeInfo->static_fields->_DesktopRcPath_k__BackingField = pSVar2;
  return;
}
"""

EXAMPLE_CODE_2 = """
/* Void set_DesktopRcPath(String) */

void NianticAuthPlugin_set_DesktopRcPath(String *value,MethodInfo *method)

{
  if (DAT_04b65fcd == '\\0') {
    FUN_00dfeb14(0xb158);
    DAT_04b65fcd = '\\x01';
  }
  NianticAuthPlugin__TypeInfo->static_fields->_DesktopRcPath_k__BackingField = value;
  return;
}
"""

COMBINED_EXAMPLE_CODE = "### CODE CONTEXT ###\n" + EXAMPLE_CODE_1 + "\n\n" + EXAMPLE_CODE_2

SYSTEM_MESSAGE_GLOBALS = """You are an expert reverse engineer. Your task is to analyze C-like pseudocode from one or more functions and suggest meaningful names for the provided list of global variables.
- You will be given code from multiple functions that reference the same global variables to provide you with maximum context.
- Examine how the global variables are used across all provided functions to infer their broader purpose. Make your best guess for a descriptive name based on this context.
- Use names that reflect the global's role or the data it holds.
- Your output must be a JSON object with a single key "global_renames", containing a list of objects with "old_name" and "new_name" keys."""
FIRST_PROMPT_GLOBALS = COMBINED_EXAMPLE_CODE + """

### GLOBALS ###
["DAT_04b65fce", "DAT_04b65fcd"]"""
FIRST_ANSWER_GLOBALS = """{
    "global_renames": [
        {"old_name": "DAT_04b65fce", "new_name": "g_LogApiInitialized"},
        {"old_name": "DAT_04b65fcd", "new_name": "g_DesktopRcPathInitialized"}
    ]
}"""

def get_global_context_code(current_func, interface, globals_to_find, max_lines=10000):
    flat_api = FlatProgramAPI(currentProgram)
    ref_manager = currentProgram.getReferenceManager()
    listing = currentProgram.getListing()

    # Decompile current function first
    decompiled_current = interface.decompileFunction(current_func, 10, ConsoleTaskMonitor())
    current_code = decompiled_current.getDecompiledFunction().getC()

    # Set of functions to avoid duplicates, initialized with the current one
    processed_functions = {current_func}

    # Find all functions that reference the globals
    for global_name in globals_to_find:
        try:
            addr = flat_api.toAddr(global_name.replace("DAT_", "0x"))
            references = ref_manager.getReferencesTo(addr)
            for ref in references:
                ref_addr = ref.getFromAddress()
                func = listing.getFunctionContaining(ref_addr)
                if func:
                    processed_functions.add(func)
        except Exception as e:
            logging.warning("Could not process references for {}: {}".format(global_name, e))

    # Remove current function from the set to handle it separately
    processed_functions.discard(current_func)

    # Decompile and collect code from other functions, sorting by size
    other_funcs_code = []
    for func in processed_functions:
        decompiled_func = interface.decompileFunction(func, 10, ConsoleTaskMonitor())
        if decompiled_func and decompiled_func.getDecompiledFunction():
            code = decompiled_func.getDecompiledFunction().getC()
            other_funcs_code.append((len(code.splitlines()), code))

    # Sort by line count (smallest first)
    other_funcs_code.sort()

    # Build the final context string
    context_code = [current_code]
    total_lines = len(current_code.splitlines())

    for line_count, code in other_funcs_code:
        if total_lines + line_count > max_lines:
            logging.info("Context code limit reached, stopping.")
            break
        context_code.append(code)
        total_lines += line_count

    return "\n\n".join(context_code)

def generate_global_renames(current_func, interface, globals_found):
    context_code = get_global_context_code(current_func, interface, globals_found)
    prompt = build_prompt(SYSTEM_MESSAGE_GLOBALS, FIRST_PROMPT_GLOBALS, FIRST_ANSWER_GLOBALS, context_code, globals_found, "GLOBALS")
    return send_prompt_to_llm(prompt, schema=SCHEMA_GLOBALS)

def find_globals_to_rename(c_code):
    return list(set(re.findall(r'\b(DAT_[0-9a-fA-F]+)\b', c_code)))

def rename_globals(old_to_new, requested_globals=None):
    flat_api = FlatProgramAPI(currentProgram)
    requested_set = set(requested_globals) if requested_globals is not None else None

    for item in old_to_new.get("global_renames", []):
        old_name, new_name = item['old_name'], item['new_name']

        if requested_set is not None and old_name not in requested_set:
            logging.warning("LLM suggested renaming for unrequested global '{}'. Skipping.".format(old_name))
            continue

        try:
            address = flat_api.toAddr(old_name.replace("DAT_", "0x"))
            symbol = flat_api.getSymbolAt(address)
            if symbol:
                logging.info('Renaming global: {} -> {}'.format(old_name, new_name))
                symbol.setName(new_name, SourceType.USER_DEFINED)
            else:
                logging.warning("Could not find global symbol for {}".format(old_name))
        except Exception as e:
            logging.error('Error renaming global {}: {}'.format(old_name, e))
