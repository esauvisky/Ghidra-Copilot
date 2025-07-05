# -*- coding: utf-8 -*-
import logging
import re
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.symbol import SourceType
from __main__ import currentProgram

from ..llm import build_prompt, send_prompt_to_llm

# --- SCHEMA ---
SCHEMA_LABELS = {
    "type": "object",
    "properties": {
        "label_renames": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "old_name": {"type": "string", "description": "The original, auto-generated name of the code label."},
                    "new_name": {"type": "string", "description": "The new, semantically meaningful name for the code label."},
                },
                "required": ["old_name", "new_name"],
            },
            "description": "A list of proposed code label renames.",
        }
    },
    "required": ["label_renames"],
}

# --- PROMPT ---
SYSTEM_MESSAGE_LABELS = """You are an expert reverse engineer. Your task is to analyze C-like pseudocode and suggest meaningful names for the provided list of code labels, typically prefixed with 'LAB_'.
- Use names that describe the purpose of the code block the label points to.
- Your output must be a JSON object with a single key "label_renames", containing a list of objects with "old_name" and "new_name" keys."""
# This example code is illustrative and not tied to a single file.
EXAMPLE_CODE_LABELS = """
void example_function() {
    /* ... */
    goto LAB_0312f230;
    /* ... */
LAB_0312f230:
  (*pVVar4->methodPtr)(pTVar2,deviceManager,pVVar4->method);
  return;
}
"""
FIRST_PROMPT_LABELS = "### CODE ###" + EXAMPLE_CODE_LABELS + """### LABELS ###
["LAB_0312f230"]"""
FIRST_ANSWER_LABELS = """{
    "label_renames": [
        {"old_name": "LAB_0312f230", "new_name": "InvokeInterfaceMethod"}
    ]
}"""

def generate_label_renames(code, labels):
    prompt = build_prompt(SYSTEM_MESSAGE_LABELS, FIRST_PROMPT_LABELS, FIRST_ANSWER_LABELS, code, labels, "LABELS")
    return send_prompt_to_llm(prompt, schema=SCHEMA_LABELS)

def find_labels_to_rename(c_code):
    return list(set(re.findall(r'^(LAB_[0-9a-fA-F]+):', c_code, re.MULTILINE)))

def rename_labels(old_to_new, requested_labels=None):
    flat_api = FlatProgramAPI(currentProgram)
    requested_set = set(requested_labels) if requested_labels is not None else None

    for item in old_to_new.get("label_renames", []):
        old_name, new_name = item['old_name'], item['new_name']

        if requested_set is not None and old_name not in requested_set:
            logging.warning("LLM suggested renaming for unrequested label '{}'. Skipping.".format(old_name))
            continue

        try:
            # Handle LAB_...
            addr_str = old_name.replace("LAB_", "0x")
            address = flat_api.toAddr(addr_str)
            symbol = flat_api.getSymbolAt(address)
            if symbol:
                logging.info('Renaming label: {} -> {}'.format(old_name, new_name))
                symbol.setName(new_name, SourceType.USER_DEFINED)
            else:
                logging.warning("Could not find label for {}".format(old_name))
        except Exception as e:
            logging.error('Error renaming label {}: {}'.format(old_name, e))
