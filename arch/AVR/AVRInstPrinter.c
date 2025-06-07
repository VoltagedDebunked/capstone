/* Capstone Disassembly Engine, http://www.capstone-engine.org */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2022, */
/* Rot127 <unisono@quyllur.org> 2022-2023 */
/* VoltagedDebunked <rusindanilo@gmail.com> 2025 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../cs_priv.h"
#include "../../utils.h"
#include "../../SStream.h"
#include "../../MCInst.h"
#include "../../MCRegisterInfo.h"
#include "AVRInstPrinter.h"
#include "AVRMapping.h"

#ifdef CAPSTONE_HAS_AVR

static const char *getRegisterName(unsigned RegNo)
{
    switch (RegNo) {
    case AVR_REG_R0: return "r0";
    case AVR_REG_R1: return "r1";
    case AVR_REG_R2: return "r2";
    case AVR_REG_R3: return "r3";
    case AVR_REG_R4: return "r4";
    case AVR_REG_R5: return "r5";
    case AVR_REG_R6: return "r6";
    case AVR_REG_R7: return "r7";
    case AVR_REG_R8: return "r8";
    case AVR_REG_R9: return "r9";
    case AVR_REG_R10: return "r10";
    case AVR_REG_R11: return "r11";
    case AVR_REG_R12: return "r12";
    case AVR_REG_R13: return "r13";
    case AVR_REG_R14: return "r14";
    case AVR_REG_R15: return "r15";
    case AVR_REG_R16: return "r16";
    case AVR_REG_R17: return "r17";
    case AVR_REG_R18: return "r18";
    case AVR_REG_R19: return "r19";
    case AVR_REG_R20: return "r20";
    case AVR_REG_R21: return "r21";
    case AVR_REG_R22: return "r22";
    case AVR_REG_R23: return "r23";
    case AVR_REG_R24: return "r24";
    case AVR_REG_R25: return "r25";
    case AVR_REG_R26: return "r26";
    case AVR_REG_R27: return "r27";
    case AVR_REG_R28: return "r28";
    case AVR_REG_R29: return "r29";
    case AVR_REG_R30: return "r30";
    case AVR_REG_R31: return "r31";
    case AVR_REG_PC: return "PC";
    case AVR_REG_SREG: return "SREG";
    default: 
        // Handle special cases for pointer registers
        if (RegNo == AVR_REG_X) return "X";
        if (RegNo == AVR_REG_Y) return "Y";
        if (RegNo == AVR_REG_Z) return "Z";
        if (RegNo == AVR_REG_SP) return "SP";
        return NULL;
    }
}

static void printRegName(SStream *O, unsigned RegNo)
{
    const char *name = getRegisterName(RegNo);
    if (name) {
        SStream_concat0(O, name);
    } else {
        SStream_concat(O, "UNKNOWN_REG_%" PRIu32, RegNo);
    }
}

static void printOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
    MCOperand *Op = MCInst_getOperand(MI, OpNo);
    
    if (MCOperand_isReg(Op)) {
        unsigned reg = MCOperand_getReg(Op);
        printRegName(O, reg);
    } else if (MCOperand_isImm(Op)) {
        int64_t imm = MCOperand_getImm(Op);
        if (imm >= 0 && imm <= 9)
            SStream_concat(O, "%"PRId64, imm);
        else
            SStream_concat(O, "$0x%"PRIx64, (uint64_t)imm);
    }
}

static void __attribute__((unused)) printImmOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
    MCOperand *Op = MCInst_getOperand(MI, OpNo);
    
    if (MCOperand_isImm(Op)) {
        int64_t imm = MCOperand_getImm(Op);
        SStream_concat(O, "0x%"PRIx64, (uint64_t)imm);
    }
}

static void __attribute__((unused)) printMemOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
    MCOperand *Base = MCInst_getOperand(MI, OpNo);
    MCOperand *Disp = MCInst_getOperand(MI, OpNo + 1);
    
    if (MCOperand_isReg(Base)) {
        printRegName(O, MCOperand_getReg(Base));
        if (MCOperand_isImm(Disp)) {
            int64_t disp = MCOperand_getImm(Disp);
            if (disp != 0) {
                SStream_concat(O, "+%"PRId64, disp);
            }
        }
    }
}

static void __attribute__((unused)) printIOOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
    MCOperand *Op = MCInst_getOperand(MI, OpNo);
    
    if (MCOperand_isImm(Op)) {
        int64_t addr = MCOperand_getImm(Op);
        SStream_concat(O, "0x%02"PRIx64, (uint64_t)addr);
    }
}

static void __attribute__((unused)) printBranchOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
    MCOperand *Op = MCInst_getOperand(MI, OpNo);
    
    if (MCOperand_isImm(Op)) {
        int64_t offset = MCOperand_getImm(Op);
        if (offset >= 0)
            SStream_concat(O, ".+%"PRId64, offset * 2 + 2);
        else
            SStream_concat(O, ".%"PRId64, offset * 2 + 2);
    }
}

void AVR_printInst(MCInst *MI, SStream *O, void *PrinterInfo)
{
    unsigned OpCode = MCInst_getOpcode(MI);
    const char *mnemonic = AVR_insn_name((csh)PrinterInfo, OpCode);
    
    if (mnemonic) {
        SStream_concat0(O, mnemonic);
    } else {
        SStream_concat(O, "UNKNOWN_%u", OpCode);
    }
    
    unsigned numOps = MCInst_getNumOperands(MI);
    if (numOps > 0) {
        SStream_concat0(O, "\t");
        
        for (unsigned i = 0; i < numOps; i++) {
            if (i > 0) {
                SStream_concat0(O, ", ");
            }
            printOperand(MI, i, O);
        }
    }
    
    // Set up instruction details for Capstone - with safety checks
    if (MI->flat_insn && MI->flat_insn->detail) {
        cs_avr *avr = &(MI->flat_insn->detail->avr);
        if (avr) {
            avr->op_count = 0;
            
            // Fill in operand details
            for (unsigned i = 0; i < numOps && i < 3 && avr->op_count < 3; i++) {
                MCOperand *Op = MCInst_getOperand(MI, i);
                if (Op) {
                    cs_avr_op *op = &avr->operands[avr->op_count];
                    
                    if (MCOperand_isReg(Op)) {
                        op->type = AVR_OP_REG;
                        op->reg = MCOperand_getReg(Op);
                        avr->op_count++;
                    } else if (MCOperand_isImm(Op)) {
                        op->type = AVR_OP_IMM;
                        op->imm = (int32_t)MCOperand_getImm(Op);
                        avr->op_count++;
                    }
                }
            }
            
            // Add instruction groups - with safety check
            if (PrinterInfo) {
                AVR_get_insn_id((cs_struct *)PrinterInfo, MI->flat_insn, OpCode);
            }
        }
    }
}

#endif