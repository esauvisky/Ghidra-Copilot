# -*- coding: utf-8 -*-
import logging
import json
from __main__ import currentProgram
from pprint import pprint
import random
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
- You will be given the code for the current function, context functions and then a JSON object containing lists of symbols to rename, categorized by type (e.g., `arguments`, `local_variables`).
- Analyze all the provided code and the JSON object of symbols to rename.
- Infer the overall purpose to provide contextually relevant names.
- Use names that reflect the symbol's role, type, or usage.
- Ensure all new names are unique where appropriate (e.g., within a function's scope).
- You must provide a new name for every symbol in the input JSON.
- Your output must be a JSON object. The keys of the object will be one or more of "argument_renames", "variable_renames", "function_renames", "global_renames", "label_renames". Each key should contain a list of objects with "old_name" and "new_name" keys."""

COMBINED_EXAMPLE_CODE = "#### MAIN\n" + EXAMPLE_CODE_CALLER + "\n#### CONTEXT" + EXAMPLE_CODE_CALLEE_1 + "\n" + EXAMPLE_CODE_CALLEE_2 + "\n" + EXAMPLE_CODE_CALLEE_3 + "\n" + EXAMPLE_CODE_CALLEE_4

FIRST_PROMPT_COMBINED = (
    "### CODE\n" + COMBINED_EXAMPLE_CODE +
    "\n\n\n### SYMBOLS TO RENAME\n" +
"""{
  "variables_found": [
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
  "globals_found": [
    "DAT_04b5e9c2"
  ],
  "functions_found": [
    "FUN_00dfeb14",
    "FUN_00df69c8",
    "FUN_00e0da3c",
    "thunk_FUN_00e3d264"
  ],
  "labels_found": [
    "LAB_01419c0c",
    "LAB_01419c94"
  ]
}
"""
)

FIRST_ANSWER_COMBINED = """{
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


def get_combined_context_code(interface, current_func, globals_to_find, functions_to_rename, max_lines=10000):
    flat_api = FlatProgramAPI(currentProgram)
    ref_manager = currentProgram.getReferenceManager()
    listing = currentProgram.getListing()

    functions_to_decompile = {current_func}
    always_include = set()

    if functions_to_rename:
        for func_name in functions_to_rename:
            try:
                addr_str = func_name.split('_')[-1]
                address = flat_api.toAddr("0x" + addr_str)
                function = flat_api.getFunctionAt(address)
                if function:
                    functions_to_decompile.add(function)
                    always_include.add(function)
            except Exception as e:
                logging.warning("Could not find function {}: {}".format(func_name, e))

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

    functions_to_decompile.discard(current_func)

    # Add references to the current function if there's space
    current_func_refs = set()
    try:
        ref_manager = currentProgram.getReferenceManager()
        refs = ref_manager.getReferencesTo(current_func.getEntryPoint())
        for ref in refs:
            ref_func = listing.getFunctionContaining(ref.getFromAddress())
            if ref_func and ref_func != current_func:
                current_func_refs.add(ref_func)
    except Exception as e:
        logging.warning("Could not get references to current function: {}".format(e))

    current_length = 0
    context_code = []
    included_funcs = set()
    # First, add all always_include functions (functions_to_rename)
    for func in always_include:
        try:
            print("Decompiling function (always include): {}".format(func.getName()))
            decompiled_func = interface.decompileFunction(func, 2, ConsoleTaskMonitor())
            if decompiled_func and decompiled_func.getDecompiledFunction():
                code = decompiled_func.getDecompiledFunction().getC()
                context_code.append(code)
                included_funcs.add(func)
        except Exception as e:
            logging.warning("Could not decompile function {}: {}".format(func.getName(), e))

    # Then, add the rest, respecting max_lines
    for func in functions_to_decompile:
        if func in included_funcs:
            continue
        try:
            print("Decompiling function: {}".format(func.getName()) + ". Current length: " + str(current_length))
            decompiled_func = interface.decompileFunction(func, 2, ConsoleTaskMonitor())
            if decompiled_func and decompiled_func.getDecompiledFunction():
                code = decompiled_func.getDecompiledFunction().getC()
                current_length += len(code.splitlines())
                if current_length > max_lines:
                    logging.info("Context code limit reached, stopping.")
                    break
                context_code.append(code)
        except Exception as e:
            logging.warning("Could not decompile function {}: {}".format(func.getName(), e))

    # Add references to the current function if there's space left
    for func in current_func_refs:
        if func in included_funcs or func in functions_to_decompile:
            continue
        try:
            decompiled_func = interface.decompileFunction(func, 2, ConsoleTaskMonitor())
            if decompiled_func and decompiled_func.getDecompiledFunction():
                code = decompiled_func.getDecompiledFunction().getC()
                current_length += len(code.splitlines())
                if current_length > max_lines:
                    logging.info("Context code limit reached (refs to current), stopping.")
                    break
                context_code.append(code)
        except Exception as e:
            logging.warning("Could not decompile referencing function {}: {}".format(func.getName(), e))

    return "\n\n".join(context_code)


def generate_combined_renames(interface, current_func, current_code, **kwargs):
    items_map = {}
    if kwargs.get("variables_found"):
        items_map["variables_found"] = kwargs["variables_found"]
    if kwargs.get("arguments_found"):
        items_map["arguments_found"] = kwargs["arguments_found"]
    if kwargs.get("globals_found"):
        items_map["globals_found"] = kwargs["globals_found"]
    if kwargs.get("functions_found"):
        items_map["functions_found"] = kwargs["functions_found"]
    if kwargs.get("labels_found"):
        items_map["labels_found"] = kwargs["labels_found"]

    context_code = get_combined_context_code(
        interface,
        current_func,
        kwargs.get("globals_found"),
        kwargs.get("functions_found")
    )

    print("Building combined prompt...")
    prompt = build_combined_prompt(
        SYSTEM_MESSAGE_COMBINED,
        FIRST_PROMPT_COMBINED,
        FIRST_ANSWER_COMBINED,
        current_code,
        context_code,
        items_map
    )

    print("Sending prompt to LLM...")
    response = send_prompt_to_llm(prompt, schema=COMBINED_SCHEMA)

    # If the LLM returns a string, try to parse it as JSON
    if isinstance(response, basestring):
        try:
            return json.loads(response)
        except (json.JSONDecodeError, TypeError):
            logging.error("Failed to parse LLM response as JSON: {}".format(response))
            return None

    return response
