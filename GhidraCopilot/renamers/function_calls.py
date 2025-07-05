# -*- coding: utf-8 -*-
import logging
import re
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.symbol import SourceType
from __main__ import currentProgram
from ghidra.util.task import ConsoleTaskMonitor

from ..llm import build_prompt, send_prompt_to_llm

# --- SCHEMA ---
SCHEMA_FUNCTIONS = {
    "type": "object",
    "properties": {
        "function_renames": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "old_name": {"type": "string", "description": "The original, auto-generated name of the called function."},
                    "new_name": {"type": "string", "description": "The new, semantically meaningful name for the called function."},
                },
                "required": ["old_name", "new_name"],
            },
            "description": "A list of proposed called function renames.",
        }
    },
    "required": ["function_renames"],
}

# --- PROMPT ---
SYSTEM_MESSAGE_FUNCTIONS = """You are an expert reverse engineer. Your task is to analyze C-like pseudocode and suggest meaningful names for the provided list of called functions.
- You will be given the code of the current function, followed by the code of the functions that need renaming.
- Analyze the body of each function to be renamed, as well as how it's used in the calling context, to infer its purpose.
- Use names that reflect the function's purpose.
- Your output must be a JSON object with a single key "function_renames", containing a list of objects with "old_name" and "new_name" keys."""

EXAMPLE_CODE_CALLER = """
/* Void Release() */

void NPCPlayerMapPOIDecoration_Release(NPCPlayerMapPOIDecoration *this,MethodInfo *method)

{
  ushort uVar1;
  bool bVar2;
  VirtualInvokeData *pVVar3;
  EventHandler_1_Niantic_Holoholo_Inventory_ItemListAdapter_ItemSelectedEventArgs_ *this_00;
  MethodInfo *extraout_r1;
  MethodInfo *extraout_r1_00;
  MethodInfo *method_00;
  undefined *puVar4;
  Il2CppRuntimeInterfaceOffsetPair *in_r3;
  IAssetRequest_1_Niantic_Holoholo_Avatar_IPlayerAvatar_ *pIVar5;
  ISchedulerPromise *pIVar6;
  TapGesture *pTVar7;
  ushort uVar8;
  IAssetRequest_1_Niantic_Holoholo_Avatar_IPlayerAvatar___Class *pIVar9;
  ISchedulerPromise__Class *pIVar10;

  if (DAT_04b5e9c2 == '\\0') {
    FUN_00dfeb14(0xadb9);
    DAT_04b5e9c2 = '\\x01';
  }
  pIVar5 = this->buildAvatarRequest;
  if (pIVar5 != (IAssetRequest_1_Niantic_Holoholo_Avatar_IPlayerAvatar_ *)0x0) {
    pIVar9 = pIVar5->klass;
    uVar1 = (pIVar9->_1).interface_offsets_count;
    if (uVar1 != 0) {
      in_r3 = pIVar9->interfaceOffsets;
      uVar8 = 0;
      do {
        if (in_r3[uVar8].interfaceType ==
            (Il2CppClass *)IAssetRequest_1_Niantic_Holoholo_Avatar_IPlayerAvatar___TypeInfo) {
          pVVar3 = &(pIVar9->vtable).Release_1 + in_r3[uVar8].offset;
          goto LAB_01419c0c;
        }
        uVar8 = uVar8 + 1;
      } while (uVar8 < uVar1);
    }
    pVVar3 = (VirtualInvokeData *)
             FUN_00df69c8((int *)pIVar5,
                          (int)IAssetRequest_1_Niantic_Holoholo_Avatar_IPlayerAvatar___TypeInfo,
                          (undefined *****)&Elf32_Ehdr_00000000.e_ident_data,(undefined **)in_r3);
LAB_01419c0c:
    (*pVVar3->methodPtr)(pIVar5,pVVar3->method);
    this->buildAvatarRequest = (IAssetRequest_1_Niantic_Holoholo_Avatar_IPlayerAvatar_ *)0x0;
  }
  pIVar6 = this->ongoingProcessesCoroutine;
  if (pIVar6 != (ISchedulerPromise *)0x0) {
    pIVar10 = pIVar6->klass;
    uVar1 = (pIVar10->_1).interface_offsets_count;
    if (uVar1 != 0) {
      in_r3 = pIVar10->interfaceOffsets;
      uVar8 = 0;
      do {
        if (in_r3[uVar8].interfaceType == (Il2CppClass *)ISchedulerPromise__TypeInfo) {
          pVVar3 = &(pIVar10->vtable).Cancel + in_r3[uVar8].offset;
          goto LAB_01419c94;
        }
        uVar8 = uVar8 + 1;
      } while (uVar8 < uVar1);
    }
    pVVar3 = (VirtualInvokeData *)
             FUN_00df69c8((int *)pIVar6,(int)ISchedulerPromise__TypeInfo,
                          (undefined *****)Elf32_Ehdr_00000000.e_ident_magic_str,(undefined **)in_r3
                         );
LAB_01419c94:
    (*pVVar3->methodPtr)(pIVar6,pVVar3->method);
    this->ongoingProcessesCoroutine = (ISchedulerPromise *)0x0;
  }
  pTVar7 = this->tapGesture;
  if ((((Object_1__TypeInfo->_1).field_0x5b & 2) != 0) &&
     ((Object_1__TypeInfo->_1).cctor_finished == 0)) {
    FUN_00e0da3c((int)Object_1__TypeInfo);
  }
  puVar4 = (undefined *)0x0;
  bVar2 = Object_1_op_Inequality((Object_1 *)pTVar7,(Object_1 *)0x0,(MethodInfo *)0x0);
  method_00 = extraout_r1;
  if (bVar2) {
    pTVar7 = this->tapGesture;
    this_00 = (EventHandler_1_Niantic_Holoholo_Inventory_ItemListAdapter_ItemSelectedEventArgs_ *)
              thunk_FUN_00e3d264((int)EventHandler_1_EventArgs___TypeInfo,extraout_r1,puVar4,
                                 (undefined **)in_r3);
    EventHandler_1_Niantic_Holoholo_Inventory_ItemListAdapter_ItemSelectedEventArgs___ctor
              (this_00,(Object *)this,NPCPlayerMapPOIDecoration_HandleTapped__MethodInfo,
               EventHandler_1_EventArgs___ctor__MethodInfo);
    if (pTVar7 == (TapGesture *)0x0) {
      NullErrorException();
    }
    TapGesture_remove_Tapped(pTVar7,(EventHandler_1_EventArgs_ *)this_00,(MethodInfo *)0x0);
    method_00 = extraout_r1_00;
  }
  this->whenNPCClicked = (Action *)0x0;
  POIDecorationBase_Release((POIDecorationBase *)this,method_00);
  return;
}
"""

EXAMPLE_CODE_CALLEE_1 = """
void FUN_00dfeb14(int param_1)

{
  int *piVar1;
  int local_1c [3];

  piVar1 = (int *)(DAT_04b71680 + *(int *)(DAT_04b71684 + 0xc0) + param_1 * 8);
  local_1c[1] = 0;
  local_1c[0] = 0;
  local_1c[2] = 0;
  FUN_00dfe9c4(*piVar1,piVar1[1],local_1c);
  free((void *)0x0);
  return;
}
"""

EXAMPLE_CODE_CALLEE_2 = """
int FUN_00df69c8(int *param_1,int param_2,undefined *****param_3,undefined **param_4)

{
  int iVar1;
  uint uVar2;
  size_t *__s;
  undefined4 *puVar3;
  Il2CppObject *pIVar4;
  int *piVar5;
  undefined4 extraout_r1;
  undefined4 uVar6;
  int iVar7;
  bool bVar8;
  size_t *psStack_44;
  size_t *psStack_40;
  size_t *psStack_3c;
  size_t *psStack_38;
  size_t *psStack_34;
  size_t *psStack_30;
  size_t *psStack_2c;
  size_t *psStack_28;
  size_t *local_24;

  iVar7 = *param_1;
  iVar1 = FUN_00df682c(iVar7,param_2,(int)param_3);
  if (iVar1 == 0) {
    uVar2 = (uint)*(byte *)(iVar7 + 0xbf);
    bVar8 = (*(byte *)(iVar7 + 0xbf) & 8) == 0;
    if (!bVar8) {
      uVar2 = param_1[2];
    }
    if ((bVar8 || uVar2 == 0) ||
       (iVar1 = FUN_00e2c4a4((int)param_1,param_2,param_3,param_4), iVar1 == 0)) {
      local_24 = (size_t *)&DAT_04b77898;
      FUN_00e24c74(&psStack_40,(int **)(param_2 + 0x10),0);
      FUN_00df7660(&psStack_3c,(size_t *)"TODO Attempt to access method \' TODO",(int *)&psStack_40)
      ;
      FUN_00e6f9ec(&psStack_38,&psStack_3c);
      FUN_00e6f3b8(&psStack_38,(size_t *)&DAT_00df6ca4,
                   (undefined4 *)Elf32_Ehdr_00000000.e_ident_magic_str);
      __s = (size_t *)FUN_00e452f4(*(MethodInfo **)(*(int *)(param_2 + 0x4c) + (int)param_3 * 4));
      FUN_00e6f9ec(&psStack_34,&psStack_38);
      puVar3 = (undefined4 *)strlen((char *)__s);
      FUN_00e6f3b8(&psStack_34,__s,puVar3);
      FUN_00e6f9ec(&psStack_30,&psStack_34);
      FUN_00e6f3b8(&psStack_30,(size_t *)"TODO \' on type \' TODO",
                   (undefined4 *)(Elf32_Ehdr_00000000.e_ident_pad + 2));
      FUN_00e24c74(&psStack_44,(int **)(iVar7 + 0x10),0);
      FUN_00df7620(&psStack_2c,&psStack_30,&psStack_44);
      FUN_00e6f9ec(&psStack_28,&psStack_2c);
      FUN_00e6f3b8(&psStack_28,(size_t *)"TODO \' failed. TODO",
                   (undefined4 *)Elf32_Ehdr_00000000.e_ident_pad);
      FUN_00e6fa54(&local_24,&psStack_28);
      FUN_00e6f0c0((int *)&psStack_28);
      FUN_00e6f0c0((int *)&psStack_2c);
      FUN_00e6f0c0((int *)&psStack_44);
      FUN_00e6f0c0((int *)&psStack_30);
      FUN_00e6f0c0((int *)&psStack_34);
      FUN_00e6f0c0((int *)&psStack_38);
      FUN_00e6f0c0((int *)&psStack_3c);
      FUN_00e6f0c0((int *)&psStack_40);
      pIVar4 = (Il2CppObject *)FUN_00e2f008((byte *)local_24);
      uVar6 = 0;
      FUN_00e2d470(pIVar4,0,(undefined4 *)0x0,param_4);
      piVar5 = FUN_00e6f0c0((int *)&local_24);
      FUN_00e6f0c0((int *)&psStack_28);
      FUN_00e6f0c0((int *)&psStack_2c);
      FUN_00e6f0c0((int *)&psStack_44);
      FUN_00e6f0c0((int *)&psStack_30);
      FUN_00e6f0c0((int *)&psStack_34);
      FUN_00e6f0c0((int *)&psStack_38);
      FUN_00e6f0c0((int *)&psStack_3c);
      FUN_00e6f0c0((int *)&psStack_40);
      FUN_00e6f0c0((int *)&local_24);
                    /* WARNING: Subroutine does not return */
      ___Unwind_Resume((int)piVar5,extraout_r1,uVar6,param_4);
    }
    FUN_00df3530(*(int *)(*(int *)(iVar1 + 4) + 0xc));
  }
  return iVar1;
}
"""

EXAMPLE_CODE_CALLEE_3 = """
void FUN_00e0da3c(int param_1)

{
  bool bVar1;
  Il2CppType *pIVar2;
  Il2CppObject *pIVar3;
  int iVar4;
  undefined **ppuVar5;
  longlong *plVar6;
  int *piVar7;
  int *piVar8;
  int *piVar9;
  undefined8 uVar10;
  longlong lVar11;
  size_t *local_30;
  size_t *local_2c;
  undefined *local_28;

  if ((*(byte *)(param_1 + 0xbf) & 2) == 0) {
    return;
  }
  piVar9 = (int *)(param_1 + 0x70);
  if (*piVar9 == 1) {
    DataMemoryBarrier(0xb);
    do {
      bVar1 = (bool)hasExclusiveAccess(piVar9);
      if (bVar1) {
        *piVar9 = 1;
        goto LAB_00e0ddcc;
      }
    } while (*piVar9 == 1);
  }
  ClearExclusiveLocal();
  DataMemoryBarrier(0xb);
  FUN_00e68fe0((pthread_mutex_t **)&DAT_04b718b0);
  if (*piVar9 == 1) {
    DataMemoryBarrier(0xb);
    do {
      bVar1 = (bool)hasExclusiveAccess(piVar9);
      if (bVar1) {
        *piVar9 = 1;
        DataMemoryBarrier(0xb);
        FUN_00e68fe8((pthread_mutex_t **)&DAT_04b718b0);
        return;
      }
    } while (*piVar9 == 1);
  }
  ClearExclusiveLocal();
  piVar8 = (int *)(param_1 + 0x6c);
  DataMemoryBarrier(0xb);
  if (*piVar8 == 1) {
    DataMemoryBarrier(0xb);
    do {
      bVar1 = (bool)hasExclusiveAccess(piVar8);
      if (bVar1) {
        *piVar8 = 1;
        DataMemoryBarrier(0xb);
        FUN_00e68fe8((pthread_mutex_t **)&DAT_04b718b0);
        plVar6 = (longlong *)(param_1 + 0x78);
        lVar11 = thunk_FUN_00e46118();
        if (lVar11 == *plVar6) {
          DataMemoryBarrier(0xb);
          do {
            bVar1 = (bool)hasExclusiveAccess(plVar6);
            if (bVar1) {
              *plVar6 = lVar11;
LAB_00e0ddcc:
              DataMemoryBarrier(0xb);
              return;
            }
          } while (lVar11 == *plVar6);
        }
        ClearExclusiveLocal();
        DataMemoryBarrier(0xb);
        iVar4 = *piVar9;
        if (iVar4 == 1) {
          DataMemoryBarrier(0xb);
          do {
            bVar1 = (bool)hasExclusiveAccess(piVar9);
            if (bVar1) {
              *piVar9 = 1;
              goto LAB_00e0dd74;
            }
            iVar4 = *piVar9;
          } while (iVar4 == 1);
        }
        ClearExclusiveLocal();
LAB_00e0dd74:
        DataMemoryBarrier(0xb);
        do {
          if (iVar4 != 0) {
            return;
          }
          thunk_FUN_00e46100(1,0);
          iVar4 = *piVar9;
          if (iVar4 == 1) {
            DataMemoryBarrier(0xb);
            do {
              bVar1 = (bool)hasExclusiveAccess(piVar9);
              if (bVar1) {
                *piVar9 = 1;
                goto LAB_00e0ddbc;
              }
              iVar4 = *piVar9;
            } while (iVar4 == 1);
          }
          ClearExclusiveLocal();
LAB_00e0ddbc:
          DataMemoryBarrier(0xb);
        } while( true );
      }
    } while (*piVar8 == 1);
  }
  ClearExclusiveLocal();
  piVar7 = (int *)(param_1 + 0x78);
  DataMemoryBarrier(0xb);
  uVar10 = thunk_FUN_00e46118();
  do {
    if (*piVar7 == *piVar7 && *(int *)(param_1 + 0x7c) == *(int *)(param_1 + 0x7c)) {
      DataMemoryBarrier(0xb);
      do {
        bVar1 = (bool)hasExclusiveAccess(piVar7);
        if (bVar1) {
          *(undefined8 *)piVar7 = uVar10;
          DataMemoryBarrier(0xb);
          do {
            if (*piVar8 == *piVar8) {
              DataMemoryBarrier(0xb);
              do {
                bVar1 = (bool)hasExclusiveAccess(piVar8);
                if (bVar1) {
                  *piVar8 = 1;
                  DataMemoryBarrier(0xb);
                  FUN_00e68fe8((pthread_mutex_t **)&DAT_04b718b0);
                  local_28 = (undefined *)0x0;
                  piVar8 = (int *)FUN_00df640c(param_1);
                  if (piVar8 != (int *)0x0) {
                    FUN_00e0d6b4(piVar8,0,0,&local_28);
                  }
                  do {
                    if (*piVar9 == *piVar9) {
                      DataMemoryBarrier(0xb);
                      do {
                        bVar1 = (bool)hasExclusiveAccess(piVar9);
                        if (bVar1) {
                          *piVar9 = 1;
                          DataMemoryBarrier(0xb);
                          do {
                            ppuVar5 = *(undefined ***)(param_1 + 0x7c);
                            if (*piVar7 == *piVar7 && *(undefined ***)(param_1 + 0x7c) == ppuVar5) {
                              DataMemoryBarrier(0xb);
                              do {
                                bVar1 = (bool)hasExclusiveAccess(piVar7);
                                if (bVar1) {
                                  *piVar7 = 0;
                                  *(undefined4 *)(param_1 + 0x7c) = 0;
                                  DataMemoryBarrier(0xb);
                                  if (local_28 == (undefined *)0x0) {
                                    return;
                                  }
                                  pIVar2 = FUN_00df5f2c((Il2CppClass *)param_1);
                                  FUN_00e24c74(&local_30,(int **)pIVar2,0);
                                  FUN_00e4d7c4(&local_2c,
                                               "TODO The type initializer for \'%s\' threw an except ion. TODO"
                                               ,local_30,ppuVar5);
                                  FUN_00e6f0c0((int *)&local_30);
                                  pIVar3 = FUN_00e2e4bc((byte *)local_2c,local_28);
                                  FUN_00e2d470(pIVar3,0,(undefined4 *)0x0,ppuVar5);
                                  FUN_00e6f0c0((int *)&local_2c);
                                  return;
                                }
                              } while (*piVar7 == *piVar7 &&
                                       *(undefined ***)(param_1 + 0x7c) == ppuVar5);
                            }
                            ClearExclusiveLocal();
                            DataMemoryBarrier(0xb);
                          } while( true );
                        }
                      } while (*piVar9 == *piVar9);
                    }
                    ClearExclusiveLocal();
                    DataMemoryBarrier(0xb);
                  } while( true );
                }
              } while (*piVar8 == *piVar8);
            }
            ClearExclusiveLocal();
            DataMemoryBarrier(0xb);
          } while( true );
        }
      } while (*piVar7 == *piVar7 && *(int *)(param_1 + 0x7c) == *(int *)(param_1 + 0x7c));
    }
    ClearExclusiveLocal();
    DataMemoryBarrier(0xb);
  } while( true );
}
"""

EXAMPLE_CODE_CALLEE_4 = """
int * FUN_00e3d264(int param_1,undefined4 param_2,undefined *param_3,undefined **param_4)

{
  bool bVar1;
  int *piVar2;
  undefined4 extraout_r1;
  undefined4 uVar3;
  undefined8 uVar4;

  FUN_00df3530(param_1);
  bVar1 = FUN_00df4794(param_1);
  uVar3 = extraout_r1;
  if (bVar1) {
    uVar4 = FUN_00df47d4(param_1);
    uVar3 = (undefined4)((ulonglong)uVar4 >> 0x20);
    param_1 = (int)uVar4;
  }
  if ((*(byte *)(param_1 + 0xbe) & 0x20) == 0) {
    piVar2 = FUN_00e3d34c(param_1,uVar3,param_3,param_4);
  }
  else {
    if (*(int *)(param_1 + 4) == 0) {
      piVar2 = (int *)FUN_00e5bb84(*(uint *)(param_1 + 0x84),0,param_3,param_4);
      *piVar2 = param_1;
    }
    else {
      piVar2 = (int *)FUN_00e55744(*(uint *)(param_1 + 0x84),param_1,(int)param_3,param_4);
    }
    bVar1 = 0xfffffffe < DAT_04b72920;
    DAT_04b72920 = DAT_04b72920 + 1;
    DAT_04b72924 = DAT_04b72924 + (uint)bVar1;
  }
  if ((*(byte *)(param_1 + 0xbf) & 1) != 0) {
    FUN_00e3f654((uint)piVar2);
  }
  if (((byte)DAT_04b71dc8 & 0x80) != 0) {
    FUN_00e4cf8c(piVar2,param_1);
  }
  FUN_00e0da3c(param_1);
  return piVar2;
}
"""

COMBINED_EXAMPLE_CODE = "### CODE CONTEXT ###\n" + EXAMPLE_CODE_CALLER + "\n\n" + EXAMPLE_CODE_CALLEE_1 + "\n\n" + EXAMPLE_CODE_CALLEE_2 + "\n\n" + EXAMPLE_CODE_CALLEE_3 + "\n\n" + EXAMPLE_CODE_CALLEE_4

FIRST_PROMPT_FUNCTIONS = COMBINED_EXAMPLE_CODE + """

### FUNCTIONS ###
["FUN_00dfeb14", "FUN_00df69c8", "FUN_00e0da3c", "thunk_FUN_00e3d264"]"""
FIRST_ANSWER_FUNCTIONS = """{
    "function_renames": [
        {"old_name": "FUN_00dfeb14", "new_name": "CheckAndSetModuleInitialized"},
        {"old_name": "FUN_00df69c8", "new_name": "FindInterfaceMethod"},
        {"old_name": "FUN_00e0da3c", "new_name": "EnsureStaticClassConstructed"},
        {"old_name": "thunk_FUN_00e3d264", "new_name": "CreateEventHandlerInstance"}
    ]
}"""

def get_function_call_context_code(interface, current_code, functions_to_rename, max_lines=50000):
    flat_api = FlatProgramAPI(currentProgram)

    context_code = [current_code]
    total_lines = len(current_code.splitlines())

    for func_name in functions_to_rename:
        try:
            addr_str = func_name.split('_')[-1]
            address = flat_api.toAddr("0x" + addr_str)
            function = flat_api.getFunctionAt(address)
            if function:
                decompiled_func = interface.decompileFunction(function, 10, ConsoleTaskMonitor())
                if decompiled_func and decompiled_func.getDecompiledFunction():
                    code = decompiled_func.getDecompiledFunction().getC()
                    if total_lines + len(code.splitlines()) > max_lines:
                        logging.info("Context code limit reached, stopping.")
                        break
                    context_code.append(code)
                    total_lines += len(code.splitlines())
        except Exception as e:
            logging.warning("Could not decompile function {}: {}".format(func_name, e))

    return "\n\n".join(context_code)

def generate_function_renames(interface, current_code, functions_to_rename):
    context_code = get_function_call_context_code(interface, current_code, functions_to_rename)
    prompt = build_prompt(SYSTEM_MESSAGE_FUNCTIONS, FIRST_PROMPT_FUNCTIONS, FIRST_ANSWER_FUNCTIONS, context_code, functions_to_rename, "FUNCTIONS")
    return send_prompt_to_llm(prompt, schema=SCHEMA_FUNCTIONS)

def find_functions_to_rename(c_code):
    return list(set(re.findall(r'\b((?:thunk_)?FUN_[0-9a-fA-F]+)\b', c_code)))

def rename_functions(old_to_new, requested_funcs=None):
    flat_api = FlatProgramAPI(currentProgram)
    requested_set = set(requested_funcs) if requested_funcs is not None else None

    for item in old_to_new.get("function_renames", []):
        old_name, new_name = item['old_name'], item['new_name']

        if requested_set is not None and old_name not in requested_set:
            logging.warning("LLM suggested renaming for unrequested function '{}'. Skipping.".format(old_name))
            continue

        try:
            # Handle thunk_FUN_... and FUN_...
            addr_str = old_name.split('_')[-1]
            address = flat_api.toAddr("0x" + addr_str)
            function = flat_api.getFunctionAt(address)
            if function:
                logging.info('Renaming function: {} -> {}'.format(old_name, new_name))
                function.setName(new_name, SourceType.USER_DEFINED)
            else:
                logging.warning("Could not find function for {}".format(old_name))
        except Exception as e:
            logging.error('Error renaming function {}: {}'.format(old_name, e))
