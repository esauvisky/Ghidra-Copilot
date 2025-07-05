# -*- coding: utf-8 -*-
from __main__ import *
import logging
from pprint import pprint
import httplib
import json
import re

from ghidra.program.model.pcode import HighFunctionDBUtil
from ghidra.app.decompiler import ClangTokenGroup
from ghidra.program.flatapi import FlatProgramAPI

from ghidra.program.model.pcode import PcodeException
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.address import Address
from ghidra.app.decompiler import ClangToken

from __main__ import currentProgram, currentAddress

def is_symbol_in_stack_space(high_symbol):
    """Check if the provided symbol is in the stack address space"""
    address = high_symbol.getPCAddress()
    return address is not None and address.isStackAddress()


def get_architecture():
    """Return the architecture details of the current program."""
    arch = currentProgram.getLanguage().getProcessor().toString()
    word_size = currentProgram.getLanguage().getLanguageDescription().getSize()
    endianness = currentProgram.getLanguage().getLanguageDescription().getEndian().toString()
    logging.info("Fetched architecture details: {}, {}-bit, {}".format(arch, word_size, endianness))
    return {'arch': arch, 'word_size': word_size, 'endianness': endianness}


def lang_description(add_assembly_info=False):
    """Return language description, optionally enriched with assembly info."""
    lang = "C"
    if add_assembly_info:
        arch_details = get_architecture()
        lang = "{} {}-bit {}".format(arch_details['arch'], arch_details['word_size'], arch_details['endianness'])
    return lang


def is_auto_generated(name):
    # Heuristics for auto-generated names: ends with _\d+, iVar\d+, uVar\d+, pVar\d+, pppVar\d+, in_r\d+, extraOutTimeout\d+, local_r\d+(_\d+)? etc.
    # Also treat names like pDVar3, bVar1, bVar2, etc. as auto-generated.
    # Also treat param_1, param_2, ... and _DAT_xxx as auto-generated.
    return (
        re.match(r".*_\d+$", name)
        or re.match(r"(?:[iuapbcdst]|ppp)Var\d+$", name)
        or re.match(r"in_r\d+$", name)
        or re.match(r"extraout_r\d+$", name)
        or re.match(r"p[D-Z]Var\d+$", name)
        or re.match(r"bVar\d+$", name)
        or re.match(r"[a-zA-Z]Var\d+$", name)  # catch bVar2, cVar3, etc.
        or re.match(r"local_r\d+(_\d+)?$", name)
        or re.match(r"local_[0-9a-fA-F]+$", name)
        or re.match(r"arg\d+$", name)
        or name.startswith("param_")
        or re.match(r"_?DAT_[0-9a-fA-F]+$", name)  # allow _DAT_xxx as auto-generated
        or re.match(r"_?(?:PTR|str|unk|off|func|var)_[0-9a-fA-F]+$", name)
    )


# https://github.com/NationalSecurityAgency/ghidra/issues/1561#issuecomment-590025081
def rename_data(old_name, new_name):
    """Rename a data variable."""
    new_name = new_name.upper()
    address = int(old_name.strip('DAT_'), 16)
    flatApi = FlatProgramAPI(currentProgram)
    sym = flatApi.getSymbolAt(flatApi.toAddr(address))
    sym.setName(new_name, SourceType.USER_DEFINED)
    logging.info("Renamed Data from {} to {}".format(old_name, new_name))


def check_full_commit(high_symbol, hfunction):
    """Check if the function's prototype is affected by a symbol change."""
    if high_symbol and not high_symbol.isParameter():
        return False

    function = hfunction.getFunction()
    parameters = function.getParameters()
    local_symbol_map = hfunction.getLocalSymbolMap()
    num_params = local_symbol_map.getNumParams()

    if num_params != len(parameters):
        return True

    for i in range(num_params):
        param = local_symbol_map.getParamSymbol(i)
        storage = param.getStorage()
        if storage.compareTo(parameters[i].getVariableStorage()) != 0:
            return True

    return False

def is_name_unique(hfunction, new_name):
    """
    Check if the new name is unique within the function's namespace.
    """
    local_symbol_map = hfunction.getLocalSymbolMap()
    if new_name in local_symbol_map.getNameToSymbolMap():
        return False
    return True

# https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Decompiler/src/main/java/ghidra/app/plugin/core/decompile/actions/RenameTask.java
def rename_clang_symbol_tokens(high_symbol, new_name, token, source_type):
    """
    Prepares for renaming a variable in decompiled code.
    It may split the variable if necessary.
    Returns the updated HighSymbol on success, None on failure.
    """
    hfunction = high_symbol.getHighFunction()

    if not is_name_unique(hfunction, new_name):
        logging.error("Rename Failed: '{}' is not a unique variable name".format(new_name))
        return None

    commit_required = check_full_commit(high_symbol, hfunction)
    if commit_required:
        logging.info("Full Function prototype commit necessary!")
        exact_spot = None  # Don't try to split out if we need to commit
    else:
        logging.info("Quick rename to symbol without prototype change necessary.")
        exact_spot = token.getVarnode()

    # HighSymbol does not have setName; skip direct setName on HighSymbol
    # Only perform split if needed, and rely on DB/proper symbol renaming

    if exact_spot and not high_symbol.isNameLocked():
        try:
            var = hfunction.splitOutMergeGroup(exact_spot.getHigh(), exact_spot)
            high_symbol = var.getSymbol()
        except PcodeException as e:
            logging.error("Rename Failed: {}".format(e))
            return None

    if not high_symbol:
        logging.error("Rename Failed: No symbol")
        return None

    return high_symbol


def find_all_clang_tokens_for_symbol(decompiled, symbol_name):
    """Find all ClangTokens for a symbol in decompiled code."""
    root_group = decompiled.getCCodeMarkup()
    matched_tokens = []

    # Depth-first traversal
    stack = [root_group]
    while stack:
        token_or_group = stack.pop()
        if isinstance(token_or_group, ClangTokenGroup):
            stack.extend([t for t in token_or_group])
        elif token_or_group.getText() == symbol_name:
            matched_tokens.append(token_or_group)

    if "in_stack_" in symbol_name:
        logging.error("Marked for stack {}".format(symbol_name))
        return None

    logging.info("Found {} matching tokens for symbol {}".format(len(matched_tokens), symbol_name))
    return matched_tokens


def get_current_function(address, program):
    logging.debug("currentAddress: {}".format(address))
    listing = program.getListing()
    function = listing.getFunctionContaining(address)
    return function


def send_https_request(address, path, data, headers):
    try:
        conn = httplib.HTTPSConnection(address)
        json_req_data = json.dumps(data)
        conn.request("POST", path, json_req_data, headers)
        response = conn.getresponse()
        json_data = response.read()
        conn.close()
        try:
            data = json.loads(json_data)
            return data
        except ValueError as e:
            logging.error("Could not parse JSON response: {e}".format(e=e))
            logging.debug(json_data)
            return None
    except Exception as e:
        logging.error("Error sending HTTPS request: {e}".format(e=e))
        return None
