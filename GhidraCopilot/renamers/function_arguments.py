# -*- coding: utf-8 -*-
import logging
from ghidra.program.model.pcode import HighFunctionDBUtil
from ghidra.program.model.symbol import SourceType

from ..llm import build_prompt, send_prompt_to_llm

# --- SCHEMA ---
SCHEMA_ARGS = {
    "type": "object",
    "properties": {
        "argument_renames": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "old_name": {"type": "string", "description": "The original, auto-generated name of the function argument."},
                    "new_name": {"type": "string", "description": "The new, semantically meaningful name for the function argument."},
                },
                "required": ["old_name", "new_name"],
            },
            "description": "A list of proposed function argument renames.",
        }
    },
    "required": ["argument_renames"],
}

# --- PROMPT ---
SYSTEM_MESSAGE_ARGS = """You are an expert reverse engineer. Your task is to analyze C-like pseudocode and suggest meaningful names for the provided list of function arguments.
- Infer the function's overall purpose from its name and body to provide contextually relevant argument names. Make an educated guess if the role is not immediately clear.
- Use names that reflect the argument's role, type, or usage.
- Ensure all new names are unique.
- You must provide a new name for every argument in the input list.
- Your output must be a JSON object with a single key "argument_renames", containing a list of objects with "old_name" and "new_name" keys."""
# This example code is illustrative and not tied to a single file.
EXAMPLE_CODE_ARGS = """
void LocalizationManager_InitializeLocaleService(LocalizationManager *this,IDeviceManager *deviceManager,MethodInfo *method) {
    /* ... function body ... */
}
"""
FIRST_PROMPT_ARGS = "### CODE ###" + EXAMPLE_CODE_ARGS + """### ARGUMENTS ###
["this", "deviceManager", "method"]"""
FIRST_ANSWER_ARGS = """{
    "argument_renames": [
        {"old_name": "this", "new_name": "localizationManager"},
        {"old_name": "deviceManager", "new_name": "pDeviceManager"},
        {"old_name": "method", "new_name": "methodInfo"}
    ]
}"""

def generate_argument_renames(code, args):
    prompt = build_prompt(SYSTEM_MESSAGE_ARGS, FIRST_PROMPT_ARGS, FIRST_ANSWER_ARGS, code, args, "ARGUMENTS")
    return send_prompt_to_llm(prompt, schema=SCHEMA_ARGS)

def rename_arguments(decompiled, old_to_new, requested_args=None):
    hfunction = decompiled.getHighFunction()
    lsm = hfunction.getLocalSymbolMap()
    requested_set = set(requested_args) if requested_args is not None else None

    for item in old_to_new.get("argument_renames", []):
        old_name, new_name = item['old_name'], item['new_name']

        if requested_set is not None and old_name not in requested_set:
            logging.warning("LLM suggested renaming for unrequested argument '{}'. Skipping.".format(old_name))
            continue

        symbol = next((s for s in lsm.getSymbols() if s.getName() == old_name and s.isParameter()), None)
        if not symbol:
            logging.warning("Couldn't find argument symbol {}".format(old_name))
            continue

        logging.info('Renaming argument: {} -> {}'.format(old_name, new_name))
        try:
            symbol.getSymbol().setName(new_name, SourceType.USER_DEFINED)
            HighFunctionDBUtil.commitParamsToDatabase(hfunction, True, HighFunctionDBUtil.ReturnCommitOption.COMMIT, SourceType.USER_DEFINED)
        except Exception as e:
            logging.error('Error renaming argument {}: {}'.format(old_name, e))
