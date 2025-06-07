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

#define MAX_AVR_OPERANDS 3

// Use the existing mapping function instead of duplicating register names
static void printRegName(SStream *O, unsigned RegNo)
{
    const char *name = AVR_reg_name(0, RegNo);
    if (name) {
        SStream_concat0(O, name);
    } else {
        SStream_concat0(O, "UNKNOWN_REG_");
        printUInt32(O, RegNo);
    }
}

static void printOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
    if (OpNo >= MCInst_getNumOperands(MI)) {
        return; // Safety check
    }
    
    MCOperand *Op = MCInst_getOperand(MI, OpNo);
    
    if (MCOperand_isReg(Op)) {
        unsigned reg = MCOperand_getReg(Op);
        printRegName(O, reg);
    } else if (MCOperand_isImm(Op)) {
        int64_t imm = MCOperand_getImm(Op);
        if (imm >= 0 && imm <= 9) {
            printInt64(O, imm);
        } else {
            SStream_concat0(O, "$0x");
            printUInt64(O, (uint64_t)imm);
        }
    }
}

static void __attribute__((unused)) printImmOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
    if (OpNo >= MCInst_getNumOperands(MI)) {
        return; // Safety check
    }
    
    MCOperand *Op = MCInst_getOperand(MI, OpNo);
    
    if (MCOperand_isImm(Op)) {
        int64_t imm = MCOperand_getImm(Op);
        SStream_concat0(O, "0x");
        printUInt64(O, (uint64_t)imm);
    }
}

static void __attribute__((unused)) printMemOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
    if (OpNo + 1 >= MCInst_getNumOperands(MI)) {
        return; // Safety check
    }
    
    MCOperand *Base = MCInst_getOperand(MI, OpNo);
    MCOperand *Disp = MCInst_getOperand(MI, OpNo + 1);
    
    if (MCOperand_isReg(Base)) {
        printRegName(O, MCOperand_getReg(Base));
        if (MCOperand_isImm(Disp)) {
            int64_t disp = MCOperand_getImm(Disp);
            if (disp != 0) {
                SStream_concat0(O, "+");
                printInt64(O, disp);
            }
        }
    }
}

static void __attribute__((unused)) printIOOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
    if (OpNo >= MCInst_getNumOperands(MI)) {
        return; // Safety check
    }
    
    MCOperand *Op = MCInst_getOperand(MI, OpNo);
    
    if (MCOperand_isImm(Op)) {
        int64_t addr = MCOperand_getImm(Op);
        SStream_concat0(O, "0x");
        if (addr <= 0xFF) {
            printUInt32Bang(O, (uint32_t)addr);
        } else {
            printUInt64(O, (uint64_t)addr);
        }
    }
}

static void __attribute__((unused)) printBranchOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
    if (OpNo >= MCInst_getNumOperands(MI)) {
        return; // Safety check
    }
    
    MCOperand *Op = MCInst_getOperand(MI, OpNo);
    
    if (MCOperand_isImm(Op)) {
        int64_t offset = MCOperand_getImm(Op);
        if (offset >= 0) {
            SStream_concat0(O, ".+");
            printInt64(O, offset * 2 + 2);
        } else {
            SStream_concat0(O, ".");
            printInt64(O, offset * 2 + 2);
        }
    }
}

// Helper function to safely set operand details
static void set_operand_details(cs_avr *avr, unsigned int op_index, MCOperand *Op)
{
    if (!avr || op_index >= MAX_AVR_OPERANDS || !Op) {
        return;
    }
    
    cs_avr_op *op = &avr->operands[op_index];
    
    if (MCOperand_isReg(Op)) {
        op->type = AVR_OP_REG;
        op->reg = MCOperand_getReg(Op);
    } else if (MCOperand_isImm(Op)) {
        op->type = AVR_OP_IMM;
        op->imm = (int32_t)MCOperand_getImm(Op);
    } else {
        op->type = AVR_OP_INVALID;
    }
}

void AVR_printInst(MCInst *MI, SStream *O, void *PrinterInfo)
{
    if (!MI || !O) {
        return; // Safety check
    }
    
    unsigned OpCode = MCInst_getOpcode(MI);
    const char *mnemonic = AVR_insn_name((csh)PrinterInfo, OpCode);
    
    if (mnemonic) {
        SStream_concat0(O, mnemonic);
    } else {
        SStream_concat0(O, "UNKNOWN_");
        printUInt32(O, OpCode);
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
    
    // Set up instruction details for Capstone - with comprehensive safety checks
    if (MI->flat_insn && MI->flat_insn->detail) {
        cs_avr *avr = &(MI->flat_insn->detail->avr);
        
        // Initialize operand count
        avr->op_count = 0;
        
        // Fill in operand details with bounds checking
        unsigned max_ops = (numOps < MAX_AVR_OPERANDS) ? numOps : MAX_AVR_OPERANDS;
        for (unsigned i = 0; i < max_ops; i++) {
            MCOperand *Op = MCInst_getOperand(MI, i);
            if (Op && (MCOperand_isReg(Op) || MCOperand_isImm(Op))) {
                set_operand_details(avr, avr->op_count, Op);
                avr->op_count++;
            }
        }
        
        // Add instruction groups with safety check
        if (PrinterInfo) {
            AVR_get_insn_id((cs_struct *)PrinterInfo, MI->flat_insn, OpCode);
        }
    }
}

#endif