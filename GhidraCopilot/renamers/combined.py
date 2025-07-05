# -*- coding: utf-8 -*-
import logging
import json
from __main__ import currentProgram
from pprint import pprint
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.util.task import ConsoleTaskMonitor

from ..llm import build_combined_prompt, send_prompt_to_llm
from .function_arguments import SCHEMA_ARGS
from .local_variables import SCHEMA_LOCAL_VARS
from .function_calls import SCHEMA_FUNCTIONS
from .global_variables import SCHEMA_GLOBALS
from .labels import SCHEMA_LABELS
from .function_calls import EXAMPLE_CODE_CALLER, EXAMPLE_CODE_CALLEE_1, EXAMPLE_CODE_CALLEE_2, EXAMPLE_CODE_CALLEE_3, EXAMPLE_CODE_CALLEE_4

# --- COMBINED SCHEMA ---
COMBINED_SCHEMA = {
    "type": "object",
    "properties": {
        "argument_renames": SCHEMA_ARGS['properties']['argument_renames'],
        "variable_renames": SCHEMA_LOCAL_VARS['properties']['variable_renames'],
        "function_renames": SCHEMA_FUNCTIONS['properties']['function_renames'],
        "global_renames": SCHEMA_GLOBALS['properties']['global_renames'],
        "label_renames": SCHEMA_LABELS['properties']['label_renames'],
    },
    "required": [
        "argument_renames",
        "variable_renames",
        "function_renames",
        "global_renames",
        "label_renames"
    ]
}

# --- COMBINED PROMPT ---
SYSTEM_MESSAGE_COMBINED = """You are an expert reverse engineer. Your task is to analyze C-like pseudocode and suggest meaningful names for various symbols.
- You will be given the code for the current function (and related functions) and a JSON object containing lists of symbols to rename, categorized by type (e.g., `arguments`, `local_variables`).
- Analyze all the provided code and the JSON object of symbols to rename.
- Infer the overall purpose to provide contextually relevant names.
- Use names that reflect the symbol's role, type, or usage.
- Ensure all new names are unique where appropriate (e.g., within a function's scope).
- You must provide a new name for every symbol in the input JSON.
- Your output must be a JSON object. The keys of the object will be one or more of "argument_renames", "variable_renames", "function_renames", "global_renames", "label_renames". Each key should contain a list of objects with "old_name" and "new_name" keys."""

COMBINED_EXAMPLE_CODE = "### CODE CONTEXT ###\n" + EXAMPLE_CODE_CALLER + "\n\n" + EXAMPLE_CODE_CALLEE_1 + "\n\n" + EXAMPLE_CODE_CALLEE_2 + "\n\n" + EXAMPLE_CODE_CALLEE_3 + "\n\n" + EXAMPLE_CODE_CALLEE_4

FIRST_PROMPT_COMBINED = COMBINED_EXAMPLE_CODE + """
### SYMBOLS TO RENAME ###
{
  "arguments": [
    "this",
    "method"
  ],
  "local_variables": [
    "uVar1",
    "bVar2",
    "pVVar3",
    "this_00",
    "extraout_r1",
    "extraout_r1_00",
    "method_00",
    "puVar4",
    "in_r3",
    "pIVar5",
    "pIVar6",
    "pTVar7",
    "uVar8",
    "pIVar9",
    "pIVar10"
  ],
  "globals": [
    "DAT_04b5e9c2"
  ],
  "functions": [
    "FUN_00dfeb14",
    "FUN_00df69c8",
    "FUN_00e0da3c",
    "thunk_FUN_00e3d264"
  ],
  "labels": [
    "LAB_01419c0c",
    "LAB_01419c94"
  ]
}
"""

FIRST_ANSWER_COMBINED = """{
    "argument_renames": [
        {"old_name": "this", "new_name": "poiDecoration"},
        {"old_name": "method", "new_name": "methodInfo"}
    ],
    "variable_renames": [
        {"old_name": "uVar1", "new_name": "interfaceOffsetsCount"},
        {"old_name": "bVar2", "new_name": "isTapGestureValid"},
        {"old_name": "pVVar3", "new_name": "virtualInvokeData"},
        {"old_name": "this_00", "new_name": "eventHandler"},
        {"old_name": "extraout_r1", "new_name": "unusedMethodInfo1"},
        {"old_name": "extraout_r1_00", "new_name": "unusedMethodInfo2"},
        {"old_name": "method_00", "new_name": "currentMethodInfo"},
        {"old_name": "puVar4", "new_name": "unusedPtr"},
        {"old_name": "in_r3", "new_name": "interfaceOffsets"},
        {"old_name": "pIVar5", "new_name": "avatarRequest"},
        {"old_name": "pIVar6", "new_name": "coroutinePromise"},
        {"old_name": "pTVar7", "new_name": "tapGesture"},
        {"old_name": "uVar8", "new_name": "i"},
        {"old_name": "pIVar9", "new_name": "avatarRequestClass"},
        {"old_name": "pIVar10", "new_name": "schedulerPromiseClass"}
    ],
    "global_renames": [
        {"old_name": "DAT_04b5e9c2", "new_name": "g_NPCPlayerMapPOIDecoration_Release_Initialized"}
    ],
    "function_renames": [
        {"old_name": "FUN_00dfeb14", "new_name": "CheckAndSetModuleInitialized"},
        {"old_name": "FUN_00df69c8", "new_name": "FindInterfaceMethod"},
        {"old_name": "FUN_00e0da3c", "new_name": "EnsureStaticClassConstructed"},
        {"old_name": "thunk_FUN_00e3d264", "new_name": "CreateEventHandlerInstance"}
    ],
    "label_renames": [
        {"old_name": "LAB_01419c0c", "new_name": "ReleaseAvatarRequest"},
        {"old_name": "LAB_01419c94", "new_name": "CancelOngoingProcesses"}
    ]
}"""


def get_combined_context_code(interface, current_func, current_code, globals_to_find, functions_to_rename, max_lines=50000):
    flat_api = FlatProgramAPI(currentProgram)
    ref_manager = currentProgram.getReferenceManager()
    listing = currentProgram.getListing()

    functions_to_decompile = {current_func}

    if globals_to_find:
        for global_name in globals_to_find:
            try:
                addr = flat_api.toAddr(global_name.replace("DAT_", "0x"))
                references = ref_manager.getReferencesTo(addr)
                for ref in references:
                    func = listing.getFunctionContaining(ref.getFromAddress())
                    if func:
                        functions_to_decompile.add(func)
            except Exception as e:
                logging.warning("Could not process references for {}: {}".format(global_name, e))

    if functions_to_rename:
        for func_name in functions_to_rename:
            try:
                addr_str = func_name.split('_')[-1]
                address = flat_api.toAddr("0x" + addr_str)
                function = flat_api.getFunctionAt(address)
                if function:
                    functions_to_decompile.add(function)
            except Exception as e:
                logging.warning("Could not find function {}: {}".format(func_name, e))

    functions_to_decompile.discard(current_func)

    other_funcs_code = []
    for func in functions_to_decompile:
        try:
            decompiled_func = interface.decompileFunction(func, 10, ConsoleTaskMonitor())
            if decompiled_func and decompiled_func.getDecompiledFunction():
                code = decompiled_func.getDecompiledFunction().getC()
                other_funcs_code.append((len(code.splitlines()), code))
        except Exception as e:
            logging.warning("Could not decompile function {}: {}".format(func.getName(), e))

    other_funcs_code.sort()

    context_code = [current_code]
    total_lines = len(current_code.splitlines())

    for line_count, code in other_funcs_code:
        if total_lines + line_count > max_lines:
            logging.info("Context code limit reached, stopping.")
            break
        context_code.append(code)
        total_lines += line_count

    return "\n\n".join(context_code)


def generate_combined_renames(interface, current_func, current_code, **kwargs):
    items_map = {}
    if kwargs.get("local_vars"):
        items_map["LOCAL VARIABLES"] = kwargs["local_vars"]
    if kwargs.get("arguments"):
        items_map["ARGUMENTS"] = kwargs["arguments"]
    if kwargs.get("globals_found"):
        items_map["GLOBALS"] = kwargs["globals_found"]
    if kwargs.get("functions_found"):
        items_map["FUNCTIONS"] = kwargs["functions_found"]
    if kwargs.get("labels_found"):
        items_map["LABELS"] = kwargs["labels_found"]

    context_code = get_combined_context_code(
        interface,
        current_func,
        current_code,
        kwargs.get("globals_found"),
        kwargs.get("functions_found")
    )

    prompt = build_combined_prompt(
        SYSTEM_MESSAGE_COMBINED,
        FIRST_PROMPT_COMBINED,
        FIRST_ANSWER_COMBINED,
        context_code,
        items_map
    )

    response = send_prompt_to_llm(prompt, schema=COMBINED_SCHEMA)

    # If the LLM returns a string, try to parse it as JSON
    if isinstance(response, basestring):
        try:
            return json.loads(response)
        except (json.JSONDecodeError, TypeError):
            logging.error("Failed to parse LLM response as JSON: {}".format(response))
            return None

    return response
