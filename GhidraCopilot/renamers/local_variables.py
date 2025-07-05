# -*- coding: utf-8 -*-
import logging
from ghidra.program.model.pcode import HighFunctionDBUtil
from ghidra.program.model.symbol import SourceType

from ..llm import build_prompt, send_prompt_to_llm

# --- SCHEMA ---
SCHEMA_LOCAL_VARS = {
    "type": "object",
    "properties": {
        "variable_renames": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "old_name": {"type": "string", "description": "The original, auto-generated name of the local variable."},
                    "new_name": {"type": "string", "description": "The new, semantically meaningful name for the local variable."},
                },
                "required": ["old_name", "new_name"],
            },
            "description": "A list of proposed local variable renames.",
        }
    },
    "required": ["variable_renames"],
}

# --- PROMPT ---
SYSTEM_MESSAGE_LOCAL_VARS = """You are an expert reverse engineer. Your task is to analyze C-like pseudocode and suggest meaningful names for the provided list of local variables.
- Analyze the function's overall purpose and context to make educated guesses for variable names.
- Use names that reflect the variable's role, type, or usage.
- For simple, temporary variables (like loop counters or flags), use short, conventional names (e.g., `i`, `j`, `k`, `idx`, `flag`).
- For less critical or less frequently used variables, prefer shorter names.
- For other variables, be descriptive but concise.
- Ensure all new names are unique within the function's scope. Avoid using names that are already present as arguments or other local variables.
- You must provide a new name for every variable in the input list.
- Your output must be a JSON object with a single key "variable_renames", containing a list of objects with "old_name" and "new_name" keys."""
# This example code is illustrative and not tied to a single file.
EXAMPLE_CODE_LOCAL_VARS = """
/* Void HandleFriendDetailResponse(GetFriendDetailsResponse,
   Promise`1[Niantic.Platform.CrossGameSocial.FriendStatusDetails]) */

void NianticFriendService_HandleFriendDetailResponse
               (NianticFriendService *this,GetFriendDetailsResponse *response,
               Promise_1_Niantic_Platform_CrossGameSocial_FriendStatusDetails_ *promise,
               MethodInfo *method)

{
  GetFriendDetailsResponse_Types_Result__Enum GVar1;
  RepeatedField_1_Niantic_Platform_Protos_GetFriendDetailsResponse_Types_FriendDetailsEntryProto_
  *this_00;
  int32_t iVar2;
  int32_t iVar1;
  GetFriendDetailsResponse_Types_FriendDetailsEntryProto *this_01;
  AssetDigestOutProto *completionValue;
  GetFriendDetailsResponse_Types_PlayerStatusDetailsProto *pGVar3;
  String *pSVar4;
  GetFriendDetailsResponse_Types_PlayerStatusDetailsProto *this_02;
  SocialV2Enum_Types_OnlineStatus__Enum SVar5;
  Object *arg0;
  String *message;
  undefined4 extraout_r1;
  MethodInfo *pMVar6;
  int *local_1c;

  if (DAT_04b6e79e == '\0') {
    thunk_FUN_00dfeb14(0xb15b);
    DAT_04b6e79e = '\x01';
  }
  if (response == (GetFriendDetailsResponse *)0x0) {
    NullErrorException();
    GVar1 = GetFriendDetailsResponse_get_Result((GetFriendDetailsResponse *)0x0,(MethodInfo *)0x0);
    NullErrorException();
  }
  else {
    GVar1 = GetFriendDetailsResponse_get_Result(response,(MethodInfo *)0x0);
  }
  if (GVar1 == GetFriendDetailsResponse_Types_Result__Enum_SUCCESS) {
    this_00 = GetFriendDetailsResponse_get_FriendDetails(response,(MethodInfo *)0x0);
    if (this_00 ==
        (RepeatedField_1_Niantic_Platform_Protos_GetFriendDetailsResponse_Types_FriendDetailsEntryPr oto_
         *)0x0) {
      NullErrorException();
    }
    iVar2 = RepeatedField_1_Holoholo_Rpc_QuestConditionProto__get_Count
                      ((RepeatedField_1_Holoholo_Rpc_QuestConditionProto_ *)this_00,
                       RepeatedField_1_Niantic_Platform_Protos_GetFriendDetailsResponse_Types_Friend DetailsEntryProto__get_Count__MethodInfo
                      );
    if (0 < iVar2) {
      if (this_00 ==
          (RepeatedField_1_Niantic_Platform_Protos_GetFriendDetailsResponse_Types_FriendDetailsEntry Proto_
           *)0x0) {
        NullErrorException();
      }
      iVar1 = RepeatedField_1_Holoholo_Rpc_QuestConditionProto__get_Count
                        ((RepeatedField_1_Holoholo_Rpc_QuestConditionProto_ *)this_00,
                         RepeatedField_1_Niantic_Platform_Protos_GetFriendDetailsResponse_Types_Frie ndDetailsEntryProto__get_Count__MethodInfo
                        );
      if (iVar1 < 2) {
        if (this_00 ==
            (RepeatedField_1_Niantic_Platform_Protos_GetFriendDetailsResponse_Types_FriendDetailsEnt ryProto_
             *)0x0) {
          NullErrorException();
        }
        pMVar6 =
        RepeatedField_1_Niantic_Platform_Protos_GetFriendDetailsResponse_Types_FriendDetailsEntryPro to__get_Item__MethodInfo
        ;
        this_01 = (GetFriendDetailsResponse_Types_FriendDetailsEntryProto *)
                  RepeatedField_1_Holoholo_Rpc_QuestGoalProto__get_Item
                            ((RepeatedField_1_Holoholo_Rpc_QuestGoalProto_ *)this_00,0,
                             RepeatedField_1_Niantic_Platform_Protos_GetFriendDetailsResponse_Types_ FriendDetailsEntryProto__get_Item__MethodInfo
                            );
        completionValue =
             (AssetDigestOutProto *)
             thunk_FUN_00e3d264((int)FriendStatusDetails__TypeInfo,extraout_r1,(undefined *)pMVar6,
                                &method->methodPointer);
        FriendStatusDetails__ctor((FriendStatusDetails *)completionValue,(MethodInfo *)0x0);
        if (this_01 == (GetFriendDetailsResponse_Types_FriendDetailsEntryProto *)0x0) {
          NullErrorException();
        }
        pGVar3 = GetFriendDetailsResponse_Types_FriendDetailsEntryProto_get_PlayerStatus
                           (this_01,(MethodInfo *)0x0);
        if (pGVar3 == (GetFriendDetailsResponse_Types_PlayerStatusDetailsProto *)0x0) {
          NullErrorException();
        }
        pSVar4 = GetFriendDetailsResponse_Types_PlayerStatusDetailsProto_get_LastPlayedAppKey
                           (pGVar3,(MethodInfo *)0x0);
        if (completionValue == (AssetDigestOutProto *)0x0) {
          NullErrorException();
        }
        *(String **)&completionValue->field_0xc = pSVar4;
        if (this_01 == (GetFriendDetailsResponse_Types_FriendDetailsEntryProto *)0x0) {
          NullErrorException();
        }
        this_02 = GetFriendDetailsResponse_Types_FriendDetailsEntryProto_get_PlayerStatus
                            (this_01,(MethodInfo *)0x0);
        if (this_02 == (GetFriendDetailsResponse_Types_PlayerStatusDetailsProto *)0x0) {
          NullErrorException();
        }
        SVar5 = GetFriendDetailsResponse_Types_PlayerStatusDetailsProto_get_OnlineStatus
                          (this_02,(MethodInfo *)0x0);
        *(bool *)&completionValue->digest_ =
             SVar5 == SocialV2Enum_Types_OnlineStatus__Enum_STATUS_ONLINE;
        if (promise == (Promise_1_Niantic_Platform_CrossGameSocial_FriendStatusDetails_ *)0x0) {
          NullErrorException();
        }
        Promise_1_Holoholo_Rpc_AssetDigestOutProto__Complete
                  ((Promise_1_Holoholo_Rpc_AssetDigestOutProto_ *)promise,completionValue,
                   Promise_1_Niantic_Platform_CrossGameSocial_FriendStatusDetails__Complete__MethodI nfo
                  );
        return;
      }
    }
    if (promise == (Promise_1_Niantic_Platform_CrossGameSocial_FriendStatusDetails_ *)0x0) {
      NullErrorException();
    }
    Promise_1_Holoholo_Rpc_AssetDigestOutProto__Error
              ((Promise_1_Holoholo_Rpc_AssetDigestOutProto_ *)promise,
               StringLiteral_Incorrect_number_of_details_retu,
               Promise_1_Niantic_Platform_CrossGameSocial_FriendStatusDetails__Error__MethodInfo);
    return;
  }
  local_1c = (int *)GetFriendDetailsResponse_get_Result(response,(MethodInfo *)0x0);
  arg0 = (Object *)
         thunk_FUN_00e3ce1c((int)GetFriendDetailsResponse_Types_Result__Enum__TypeInfo,&local_1c,
                            (undefined *)GetFriendDetailsResponse_Types_Result__Enum__TypeInfo,
                            &method->methodPointer);
  message = String_Format(StringLiteral_Failed_to_get_friend_details_wit,arg0,(MethodInfo *)0x0);
  if (promise == (Promise_1_Niantic_Platform_CrossGameSocial_FriendStatusDetails_ *)0x0) {
    NullErrorException();
  }
  Promise_1_Holoholo_Rpc_AssetDigestOutProto__Error
            ((Promise_1_Holoholo_Rpc_AssetDigestOutProto_ *)promise,message,
             Promise_1_Niantic_Platform_CrossGameSocial_FriendStatusDetails__Error__MethodInfo);
  return;
}
"""
FIRST_PROMPT_LOCAL_VARS = "### CODE ###" + EXAMPLE_CODE_LOCAL_VARS + """### LOCAL VARIABLES ###
["GVar1", "this_00", "iVar2", "iVar1", "this_01", "pGVar3", "pSVar4", "this_02", "SVar5", "arg0", "extraout_r1", "pMVar6", "local_1c"]"""
FIRST_ANSWER_LOCAL_VARS = """{
    "variable_renames": [
        {"old_name": "GVar1", "new_name": "result"},
        {"old_name": "this_00", "new_name": "friendDetailsList"},
        {"old_name": "iVar2", "new_name": "entryCount"},
        {"old_name": "iVar1", "new_name": "entryCount2"},
        {"old_name": "this_01", "new_name": "firstEntry"},
        {"old_name": "pGVar3", "new_name": "playerStatus"},
        {"old_name": "pSVar4", "new_name": "lastPlayedAppKey"},
        {"old_name": "this_02", "new_name": "playerStatus2"},
        {"old_name": "SVar5", "new_name": "onlineStatus"},
        {"old_name": "arg0", "new_name": "resultBoxed"},
        {"old_name": "extraout_r1", "new_name": "unusedOut"},
        {"old_name": "pMVar6", "new_name": "getItemMI"},
        {"old_name": "local_1c", "new_name": "resultEnumPtr"},
    ]
}"""

def generate_local_variable_renames(code, variables):
    prompt = build_prompt(SYSTEM_MESSAGE_LOCAL_VARS, FIRST_PROMPT_LOCAL_VARS, FIRST_ANSWER_LOCAL_VARS, code, variables, "LOCAL VARIABLES")
    return send_prompt_to_llm(prompt, schema=SCHEMA_LOCAL_VARS)

def split_local_variables(decompiled, local_vars_to_split):
    """
    Forces split of local variable merge groups by updating them with a null name.
    This gives more granular variables to the LLM.
    """
    hfunction = decompiled.getHighFunction()
    lsm = hfunction.getLocalSymbolMap()

    # Use a set to avoid processing the same name multiple times
    for var_name in set(local_vars_to_split):
        # We need to find all symbols that match the name, as there might be several
        # fragments of a merged variable.
        symbols_to_process = [s for s in lsm.getSymbols() if s.getName() == var_name and not s.isParameter()]

        if not symbols_to_process:
            logging.warning("Couldn't find local variable symbol to split: {}".format(var_name))
            continue

        logging.info("Splitting merge group for local variable: {}".format(var_name))
        for symbol in symbols_to_process:
            try:
                # Calling updateDBVariable with a null name and null data-type on a HighSymbol
                # can cause it to be split from any larger merge group it belongs to.
                HighFunctionDBUtil.updateDBVariable(symbol, None, symbol.getDataType(), SourceType.ANALYSIS)
            except Exception as e:
                logging.error('Error splitting symbol {}: {}'.format(var_name, e))

def rename_local_variables(decompiled, old_to_new, requested_vars=None):
    hfunction = decompiled.getHighFunction()
    lsm = hfunction.getLocalSymbolMap()
    name_counts = {}
    requested_set = set(requested_vars) if requested_vars is not None else None

    for item in old_to_new.get("variable_renames", []):
        old_name, new_name = item['old_name'], item['new_name']

        if requested_set is not None and old_name not in requested_set:
            logging.warning("LLM suggested renaming for unrequested local variable '{}'. Skipping.".format(old_name))
            continue

        if new_name in name_counts:
            name_counts[new_name] += 1
            new_name = "{}_{}".format(new_name, name_counts[new_name])
        else:
            name_counts[new_name] = 1

        symbol = next((s for s in lsm.getSymbols() if s.getName() == old_name and not s.isParameter()), None)
        if not symbol:
            logging.warning("Couldn't find local variable symbol {}".format(old_name))
            continue

        logging.info('Renaming local variable: {} -> {}'.format(old_name, new_name))
        try:
            # By passing None as the DataType, we avoid splitting the variable group.
            HighFunctionDBUtil.updateDBVariable(symbol, new_name, None, SourceType.USER_DEFINED) # type: ignore
        except Exception as e:
            logging.error('Error renaming symbol {}: {}'.format(old_name, e))
