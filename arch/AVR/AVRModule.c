/* Capstone Disassembly Engine, http://www.capstone-engine.org */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2022, */
/* Rot127 <unisono@quyllur.org> 2022-2023 */
/* VoltagedDebunked <rusindanilo@gmail.com> 2025 */

#ifdef CAPSTONE_HAS_AVR

#include "../../cs_priv.h"
#include "../../MCRegisterInfo.h"
#include "AVRDisassembler.h"
#include "AVRInstPrinter.h"
#include "AVRMapping.h"
#include "AVRModule.h"

// Register descriptors
static const MCRegisterDesc AVRRegDesc[] = {
    { 0, 0, 0, 0, 0, 0 }, // Invalid register
    // General purpose registers R0-R31
    { 1, 0, 0, 0, 0, 0 }, // R0
    { 2, 0, 0, 0, 0, 0 }, // R1
    { 3, 0, 0, 0, 0, 0 }, // R2
    { 4, 0, 0, 0, 0, 0 }, // R3
    { 5, 0, 0, 0, 0, 0 }, // R4
    { 6, 0, 0, 0, 0, 0 }, // R5
    { 7, 0, 0, 0, 0, 0 }, // R6
    { 8, 0, 0, 0, 0, 0 }, // R7
    { 9, 0, 0, 0, 0, 0 }, // R8
    { 10, 0, 0, 0, 0, 0 }, // R9
    { 11, 0, 0, 0, 0, 0 }, // R10
    { 12, 0, 0, 0, 0, 0 }, // R11
    { 13, 0, 0, 0, 0, 0 }, // R12
    { 14, 0, 0, 0, 0, 0 }, // R13
    { 15, 0, 0, 0, 0, 0 }, // R14
    { 16, 0, 0, 0, 0, 0 }, // R15
    { 17, 0, 0, 0, 0, 0 }, // R16
    { 18, 0, 0, 0, 0, 0 }, // R17
    { 19, 0, 0, 0, 0, 0 }, // R18
    { 20, 0, 0, 0, 0, 0 }, // R19
    { 21, 0, 0, 0, 0, 0 }, // R20
    { 22, 0, 0, 0, 0, 0 }, // R21
    { 23, 0, 0, 0, 0, 0 }, // R22
    { 24, 0, 0, 0, 0, 0 }, // R23
    { 25, 0, 0, 0, 0, 0 }, // R24
    { 26, 0, 0, 0, 0, 0 }, // R25
    { 27, 0, 0, 0, 0, 0 }, // R26 (X low)
    { 28, 0, 0, 0, 0, 0 }, // R27 (X high)
    { 29, 0, 0, 0, 0, 0 }, // R28 (Y low)
    { 30, 0, 0, 0, 0, 0 }, // R29 (Y high)
    { 31, 0, 0, 0, 0, 0 }, // R30 (Z low)
    { 32, 0, 0, 0, 0, 0 }, // R31 (Z high)
    // Pointer registers
    { 33, 0, 0, 0, 0, 0 }, // X
    { 34, 0, 0, 0, 0, 0 }, // Y
    { 35, 0, 0, 0, 0, 0 }, // Z
    // Special registers
    { 36, 0, 0, 0, 0, 0 }, // SP
    { 37, 0, 0, 0, 0, 0 }, // PC
    { 38, 0, 0, 0, 0, 0 }, // SREG
};

// Register arrays for classes
static const MCPhysReg AVRGPRRegs[] = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32
};

static const MCPhysReg AVRGPRHighRegs[] = {
    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32
};

static const MCPhysReg AVRPtrRegs[] = {
    33, 34, 35  // X, Y, Z
};

// Register classes
static const MCRegisterClass AVRMCRegisterClasses[] = {
    { AVRGPRRegs, NULL, 32 },
    { AVRGPRHighRegs, NULL, 16 },
    { AVRPtrRegs, NULL, 3 },
};

// Register difference lists (simple array of MCPhysReg for Capstone)
static const MCPhysReg AVRRegDiffLists[] = {
    0
};

// Sub-register index lists (empty for AVR)
static const uint16_t AVRSubRegIdxLists[] = {
    0
};

// Register encoding table
static const uint16_t AVRRegEncodingTable[] = {
    0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    26, 28, 30, // X, Y, Z
    31, 32, 33  // SP, PC, SREG
};

cs_err AVR_global_init(cs_struct *ud)
{
    MCRegisterInfo *mri;
    mri = cs_mem_malloc(sizeof(*mri));
    
    MCRegisterInfo_InitMCRegisterInfo(mri, AVRRegDesc, sizeof(AVRRegDesc)/sizeof(AVRRegDesc[0]),
                                     0, 0, AVRMCRegisterClasses,
                                     sizeof(AVRMCRegisterClasses)/sizeof(AVRMCRegisterClasses[0]), 0, 0,
                                     AVRRegDiffLists, 0, AVRSubRegIdxLists,
                                     sizeof(AVRSubRegIdxLists)/sizeof(AVRSubRegIdxLists[0]),
                                     AVRRegEncodingTable);
    
    ud->printer = AVR_printInst;
    ud->printer_info = mri;
    ud->getinsn_info = mri;
    ud->disasm = AVR_getInstruction;
    ud->post_printer = NULL;
    
    ud->reg_name = AVR_reg_name;
    ud->insn_id = AVR_get_insn_id;
    ud->insn_name = AVR_insn_name;
    ud->group_name = AVR_group_name;
    ud->reg_access = AVR_reg_access;
    
    return CS_ERR_OK;
}

cs_err AVR_option(cs_struct *handle, cs_opt_type type, size_t value)
{
    if (type == CS_OPT_SYNTAX)
        handle->syntax = (int) value;
    
    return CS_ERR_OK;
}

#endif