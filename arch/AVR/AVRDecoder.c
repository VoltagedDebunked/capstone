/* Capstone Disassembly Engine, http://www.capstone-engine.org */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2022, */
/* Rot127 <unisono@quyllur.org> 2022-2023 */
/* VoltagedDebunked <rusindanilo@gmail.com> 2025 */

#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include "../../cs_priv.h"
#include "../../MCInst.h"
#include "../../MCInstrDesc.h"
#include "../../MCFixedLenDisassembler.h"
#include "../../MCRegisterInfo.h"
#include "../../MCDisassembler.h"
#include "../../utils.h"
#include "../../MathExtras.h"
#include "AVRDisassembler.h"
#include "AVRMapping.h"

#ifdef CAPSTONE_HAS_AVR

// Addressing mode enumeration
typedef enum {
    AVR_AM_NORMAL = 0,    // Normal addressing
    AVR_AM_POST_INC = 1,  // Post-increment
    AVR_AM_PRE_DEC = 2    // Pre-decrement
} avr_addressing_mode_t;

// Instruction decoder table for 16-bit instructions
typedef struct {
    uint16_t mask;
    uint16_t pattern;
    unsigned instruction;
    DecodeStatus (*decoder)(MCInst *, uint16_t, uint64_t, const void *);
} avr_decode16_entry_t;

// Instruction decoder table for 32-bit instructions
typedef struct {
    uint32_t mask;
    uint32_t pattern;
    unsigned instruction;
    DecodeStatus (*decoder)(MCInst *, uint32_t, uint64_t, const void *);
} avr_decode32_entry_t;

// Forward declarations of decoder functions
static DecodeStatus DecodeRdRr(MCInst *MI, uint16_t insn, uint64_t addr, const void *decoder);
static DecodeStatus DecodeRdK8(MCInst *MI, uint16_t insn, uint64_t addr, const void *decoder);
static DecodeStatus DecodeRdK6(MCInst *MI, uint16_t insn, uint64_t addr, const void *decoder);
static DecodeStatus DecodeRd(MCInst *MI, uint16_t insn, uint64_t addr, const void *decoder);
static DecodeStatus DecodeBranch(MCInst *MI, uint16_t insn, uint64_t addr, const void *decoder);
static DecodeStatus DecodeIOBit(MCInst *MI, uint16_t insn, uint64_t addr, const void *decoder);
static DecodeStatus DecodeRegBit(MCInst *MI, uint16_t insn, uint64_t addr, const void *decoder);
static DecodeStatus DecodeSkipBit(MCInst *MI, uint16_t insn, uint64_t addr, const void *decoder);
static DecodeStatus DecodeIOImm(MCInst *MI, uint16_t insn, uint64_t addr, const void *decoder);
static DecodeStatus DecodeWordPair(MCInst *MI, uint16_t insn, uint64_t addr, const void *decoder);
static DecodeStatus DecodeIndirect(MCInst *MI, uint16_t insn, uint64_t addr, const void *decoder);
static DecodeStatus DecodeIndirectDisp(MCInst *MI, uint16_t insn, uint64_t addr, const void *decoder);
static DecodeStatus DecodeNoOperands(MCInst *MI, uint16_t insn, uint64_t addr, const void *decoder);
static DecodeStatus DecodeJmp32(MCInst *MI, uint32_t insn, uint64_t addr, const void *decoder);
static DecodeStatus DecodeCall32(MCInst *MI, uint32_t insn, uint64_t addr, const void *decoder);
static DecodeStatus DecodeLds32(MCInst *MI, uint32_t insn, uint64_t addr, const void *decoder);
static DecodeStatus DecodeSts32(MCInst *MI, uint32_t insn, uint64_t addr, const void *decoder);
static DecodeStatus DecodeBranchSR(MCInst *MI, uint16_t insn, uint64_t addr, const void *decoder);
static DecodeStatus DecodeRdRrMul(MCInst *MI, uint16_t insn, uint64_t addr, const void *decoder);
static DecodeStatus DecodeIOOut(MCInst *MI, uint16_t insn, uint64_t addr, const void *decoder);
static DecodeStatus DecodeStatusBit(MCInst *MI, uint16_t insn, uint64_t addr, const void *decoder);

// Sign extension helper function for 12-bit values
static inline int16_t SignExtend12(uint16_t val)
{
    return (int16_t)(val << 4) >> 4;
}

// Sign extension helper function for 7-bit values
static inline int8_t SignExtend7(uint8_t val)
{
    return (int8_t)(val << 1) >> 1;
}

// 16-bit instruction decode table - ordered by specificity (most specific first)
static const avr_decode16_entry_t decode16_table[] = {
    // Most specific patterns first to avoid conflicts
    
    // MCU Control Instructions (very specific patterns)
    { 0xFFFF, 0x0000, AVR_INS_NOP, DecodeNoOperands }, // NOP
    { 0xFFFF, 0x9588, AVR_INS_SLEEP, DecodeNoOperands }, // SLEEP
    { 0xFFFF, 0x95A8, AVR_INS_WDR, DecodeNoOperands }, // WDR
    { 0xFFFF, 0x9598, AVR_INS_BREAK, DecodeNoOperands }, // BREAK
    { 0xFFFF, 0x9508, AVR_INS_RET, DecodeNoOperands }, // RET
    { 0xFFFF, 0x9518, AVR_INS_RETI, DecodeNoOperands }, // RETI
    { 0xFFFF, 0x9409, AVR_INS_IJMP, DecodeNoOperands }, // IJMP
    { 0xFFFF, 0x9419, AVR_INS_EIJMP, DecodeNoOperands }, // EIJMP
    { 0xFFFF, 0x9509, AVR_INS_ICALL, DecodeNoOperands }, // ICALL
    { 0xFFFF, 0x9519, AVR_INS_EICALL, DecodeNoOperands }, // EICALL
    
    // Program Memory Instructions
    { 0xFFFF, 0x95C8, AVR_INS_LPM, DecodeNoOperands }, // LPM
    { 0xFFFF, 0x95D8, AVR_INS_ELPM, DecodeNoOperands }, // ELPM
    { 0xFFFF, 0x95E8, AVR_INS_SPM, DecodeNoOperands }, // SPM
    { 0xFFFF, 0x95F8, AVR_INS_SPM, DecodeNoOperands }, // SPM Z+
    
    // Status Register Instructions (specific bit patterns)
    { 0xFFFF, 0x9408, AVR_INS_SEC, DecodeNoOperands }, // SEC
    { 0xFFFF, 0x9488, AVR_INS_CLC, DecodeNoOperands }, // CLC
    { 0xFFFF, 0x9428, AVR_INS_SEN, DecodeNoOperands }, // SEN
    { 0xFFFF, 0x94A8, AVR_INS_CLN, DecodeNoOperands }, // CLN
    { 0xFFFF, 0x9418, AVR_INS_SEZ, DecodeNoOperands }, // SEZ
    { 0xFFFF, 0x9498, AVR_INS_CLZ, DecodeNoOperands }, // CLZ
    { 0xFFFF, 0x9478, AVR_INS_SEI, DecodeNoOperands }, // SEI
    { 0xFFFF, 0x94F8, AVR_INS_CLI, DecodeNoOperands }, // CLI
    { 0xFFFF, 0x9448, AVR_INS_SES, DecodeNoOperands }, // SES
    { 0xFFFF, 0x94C8, AVR_INS_CLS, DecodeNoOperands }, // CLS
    { 0xFFFF, 0x9438, AVR_INS_SEV, DecodeNoOperands }, // SEV
    { 0xFFFF, 0x94B8, AVR_INS_CLV, DecodeNoOperands }, // CLV
    { 0xFFFF, 0x9468, AVR_INS_SET, DecodeNoOperands }, // SET
    { 0xFFFF, 0x94E8, AVR_INS_CLT, DecodeNoOperands }, // CLT
    { 0xFFFF, 0x9458, AVR_INS_SEH, DecodeNoOperands }, // SEH
    { 0xFFFF, 0x94D8, AVR_INS_CLH, DecodeNoOperands }, // CLH
    
    // Generic BSET/BCLR (less specific)
    { 0xFF8F, 0x9408, AVR_INS_BSET, DecodeStatusBit }, // BSET s
    { 0xFF8F, 0x9488, AVR_INS_BCLR, DecodeStatusBit }, // BCLR s
    
    // Single register operations
    { 0xFE0F, 0x9400, AVR_INS_COM, DecodeRd },       // COM Rd
    { 0xFE0F, 0x9401, AVR_INS_NEG, DecodeRd },       // NEG Rd
    { 0xFE0F, 0x9403, AVR_INS_INC, DecodeRd },       // INC Rd
    { 0xFE0F, 0x940A, AVR_INS_DEC, DecodeRd },       // DEC Rd
    { 0xFE0F, 0x9406, AVR_INS_LSR, DecodeRd },       // LSR Rd
    { 0xFE0F, 0x9407, AVR_INS_ROR, DecodeRd },       // ROR Rd
    { 0xFE0F, 0x9405, AVR_INS_ASR, DecodeRd },       // ASR Rd
    { 0xFE0F, 0x9402, AVR_INS_SWAP, DecodeRd },      // SWAP Rd
    
    // Stack operations
    { 0xFE0F, 0x920F, AVR_INS_PUSH, DecodeRd },      // PUSH Rr
    { 0xFE0F, 0x900F, AVR_INS_POP, DecodeRd },       // POP Rd
    
    // Load/Store with specific addressing modes
    { 0xFE0F, 0x900C, AVR_INS_LD, DecodeIndirect },  // LD Rd, X
    { 0xFE0F, 0x900D, AVR_INS_LD, DecodeIndirect },  // LD Rd, X+
    { 0xFE0F, 0x900E, AVR_INS_LD, DecodeIndirect },  // LD Rd, -X
    { 0xFE0F, 0x8008, AVR_INS_LD, DecodeIndirect },  // LD Rd, Y
    { 0xFE0F, 0x9009, AVR_INS_LD, DecodeIndirect },  // LD Rd, Y+
    { 0xFE0F, 0x900A, AVR_INS_LD, DecodeIndirect },  // LD Rd, -Y
    { 0xFE0F, 0x8000, AVR_INS_LD, DecodeIndirect },  // LD Rd, Z
    { 0xFE0F, 0x9001, AVR_INS_LD, DecodeIndirect },  // LD Rd, Z+
    { 0xFE0F, 0x9002, AVR_INS_LD, DecodeIndirect },  // LD Rd, -Z
    
    // Store instructions
    { 0xFE0F, 0x920C, AVR_INS_ST, DecodeIndirect },  // ST X, Rr
    { 0xFE0F, 0x920D, AVR_INS_ST, DecodeIndirect },  // ST X+, Rr
    { 0xFE0F, 0x920E, AVR_INS_ST, DecodeIndirect },  // ST -X, Rr
    { 0xFE0F, 0x8208, AVR_INS_ST, DecodeIndirect },  // ST Y, Rr
    { 0xFE0F, 0x9209, AVR_INS_ST, DecodeIndirect },  // ST Y+, Rr
    { 0xFE0F, 0x920A, AVR_INS_ST, DecodeIndirect },  // ST -Y, Rr
    { 0xFE0F, 0x8200, AVR_INS_ST, DecodeIndirect },  // ST Z, Rr
    { 0xFE0F, 0x9201, AVR_INS_ST, DecodeIndirect },  // ST Z+, Rr
    { 0xFE0F, 0x9202, AVR_INS_ST, DecodeIndirect },  // ST -Z, Rr
    
    // LPM/ELPM with registers
    { 0xFE0F, 0x9004, AVR_INS_LPM, DecodeIndirect },  // LPM Rd, Z
    { 0xFE0F, 0x9005, AVR_INS_LPM, DecodeIndirect },  // LPM Rd, Z+
    { 0xFE0F, 0x9006, AVR_INS_ELPM, DecodeIndirect }, // ELPM Rd, Z
    { 0xFE0F, 0x9007, AVR_INS_ELPM, DecodeIndirect }, // ELPM Rd, Z+
    
    // Load/Store with displacement (less specific mask)
    { 0xD208, 0x8000, AVR_INS_LDD, DecodeIndirectDisp }, // LDD Rd, Y+q
    { 0xD208, 0x8008, AVR_INS_LDD, DecodeIndirectDisp }, // LDD Rd, Z+q
    { 0xD208, 0x8200, AVR_INS_STD, DecodeIndirectDisp }, // STD Y+q, Rr
    { 0xD208, 0x8208, AVR_INS_STD, DecodeIndirectDisp }, // STD Z+q, Rr
    
    // Bit operations
    { 0xFE08, 0xFA00, AVR_INS_BST, DecodeRegBit },   // BST Rd, b
    { 0xFE08, 0xF800, AVR_INS_BLD, DecodeRegBit },   // BLD Rd, b
    { 0xFE08, 0xFC00, AVR_INS_SBRC, DecodeSkipBit }, // SBRC Rr, b
    { 0xFE08, 0xFE00, AVR_INS_SBRS, DecodeSkipBit }, // SBRS Rr, b
    
    // Multiply Instructions (specific ranges)
    { 0xFF88, 0x0300, AVR_INS_MULSU, DecodeRdRrMul }, // MULSU Rd, Rr (R16-R23)
    { 0xFF88, 0x0308, AVR_INS_FMUL, DecodeRdRrMul },  // FMUL Rd, Rr (R16-R23)
    { 0xFF88, 0x0380, AVR_INS_FMULS, DecodeRdRrMul }, // FMULS Rd, Rr (R16-R23)
    { 0xFF88, 0x0388, AVR_INS_FMULSU, DecodeRdRrMul }, // FMULSU Rd, Rr (R16-R23)
    { 0xFF00, 0x0200, AVR_INS_MULS, DecodeRdRrMul },  // MULS Rd, Rr (R16-R31)
    
    // Word operations
    { 0xFF00, 0x0100, AVR_INS_MOVW, DecodeWordPair }, // MOVW Rd+1:Rd, Rr+1:Rr
    { 0xFF00, 0x9600, AVR_INS_ADIW, DecodeWordPair }, // ADIW Rd+1:Rd, K
    { 0xFF00, 0x9700, AVR_INS_SBIW, DecodeWordPair }, // SBIW Rd+1:Rd, K
    
    // I/O Bit operations
    { 0xFF00, 0x9900, AVR_INS_SBIC, DecodeIOBit },   // SBIC A, b
    { 0xFF00, 0x9B00, AVR_INS_SBIS, DecodeIOBit },   // SBIS A, b
    
    // Branch on Status Register (specific conditions)
    { 0xFC07, 0xF001, AVR_INS_BREQ, DecodeBranchSR }, // BREQ k
    { 0xFC07, 0xF401, AVR_INS_BRNE, DecodeBranchSR }, // BRNE k
    { 0xFC07, 0xF000, AVR_INS_BRCS, DecodeBranchSR }, // BRCS k
    { 0xFC07, 0xF400, AVR_INS_BRCC, DecodeBranchSR }, // BRCC k
    { 0xFC07, 0xF002, AVR_INS_BRMI, DecodeBranchSR }, // BRMI k
    { 0xFC07, 0xF402, AVR_INS_BRPL, DecodeBranchSR }, // BRPL k
    { 0xFC07, 0xF004, AVR_INS_BRGE, DecodeBranchSR }, // BRGE k
    { 0xFC07, 0xF404, AVR_INS_BRLT, DecodeBranchSR }, // BRLT k
    { 0xFC07, 0xF003, AVR_INS_BRHS, DecodeBranchSR }, // BRHS k
    { 0xFC07, 0xF403, AVR_INS_BRHC, DecodeBranchSR }, // BRHC k
    { 0xFC07, 0xF005, AVR_INS_BRTS, DecodeBranchSR }, // BRTS k
    { 0xFC07, 0xF405, AVR_INS_BRTC, DecodeBranchSR }, // BRTC k
    { 0xFC07, 0xF006, AVR_INS_BRVS, DecodeBranchSR }, // BRVS k
    { 0xFC07, 0xF406, AVR_INS_BRVC, DecodeBranchSR }, // BRVC k
    { 0xFC07, 0xF007, AVR_INS_BRIE, DecodeBranchSR }, // BRIE k
    { 0xFC07, 0xF407, AVR_INS_BRID, DecodeBranchSR }, // BRID k
    
    // Generic branch on status register
    { 0xFC00, 0xF000, AVR_INS_BRBS, DecodeBranchSR }, // BRBS s, k
    { 0xFC00, 0xF400, AVR_INS_BRBC, DecodeBranchSR }, // BRBC s, k
    
    // I/O Instructions
    { 0xF800, 0xB000, AVR_INS_IN, DecodeIOImm },     // IN Rd, A
    { 0xF800, 0xB800, AVR_INS_OUT, DecodeIOOut },    // OUT A, Rr
    
    // Immediate instructions (8-bit)
    { 0xF000, 0x3000, AVR_INS_CPI, DecodeRdK8 },     // CPI Rd, K
    { 0xF000, 0x4000, AVR_INS_SBCI, DecodeRdK8 },    // SBCI Rd, K
    { 0xF000, 0x5000, AVR_INS_SUBI, DecodeRdK8 },    // SUBI Rd, K
    { 0xF000, 0x6000, AVR_INS_ORI, DecodeRdK8 },     // ORI Rd, K
    { 0xF000, 0x7000, AVR_INS_ANDI, DecodeRdK8 },    // ANDI Rd, K
    { 0xF000, 0xE000, AVR_INS_LDI, DecodeRdK8 },     // LDI Rd, K
    
    // Branch Instructions
    { 0xF000, 0xC000, AVR_INS_RJMP, DecodeBranch },  // RJMP k
    { 0xF000, 0xD000, AVR_INS_RCALL, DecodeBranch }, // RCALL k
    
    // Two register operations (most general patterns last)
    { 0xFC00, 0x0400, AVR_INS_CPC, DecodeRdRr },     // CPC Rd, Rr
    { 0xFC00, 0x0800, AVR_INS_SBC, DecodeRdRr },     // SBC Rd, Rr
    { 0xFC00, 0x0C00, AVR_INS_ADD, DecodeRdRr },     // ADD Rd, Rr
    { 0xFC00, 0x1000, AVR_INS_CPSE, DecodeRdRr },    // CPSE Rd, Rr
    { 0xFC00, 0x1400, AVR_INS_CP, DecodeRdRr },      // CP Rd, Rr
    { 0xFC00, 0x1800, AVR_INS_SUB, DecodeRdRr },     // SUB Rd, Rr
    { 0xFC00, 0x1C00, AVR_INS_ADC, DecodeRdRr },     // ADC Rd, Rr
    { 0xFC00, 0x2000, AVR_INS_AND, DecodeRdRr },     // AND Rd, Rr
    { 0xFC00, 0x2400, AVR_INS_EOR, DecodeRdRr },     // EOR Rd, Rr
    { 0xFC00, 0x2800, AVR_INS_OR, DecodeRdRr },      // OR Rd, Rr
    { 0xFC00, 0x2C00, AVR_INS_MOV, DecodeRdRr },     // MOV Rd, Rr
    { 0xFC00, 0x9C00, AVR_INS_MUL, DecodeRdRr },     // MUL Rd, Rr
};

// 32-bit instruction decode table
static const avr_decode32_entry_t decode32_table[] = {
    { 0xFE0E0000, 0x940C0000, AVR_INS_JMP, DecodeJmp32 },   // JMP k
    { 0xFE0E0000, 0x940E0000, AVR_INS_CALL, DecodeCall32 }, // CALL k
    { 0xFE0F0000, 0x90000000, AVR_INS_LDS, DecodeLds32 },   // LDS Rd, k
    { 0xFE0F0000, 0x92000000, AVR_INS_STS, DecodeSts32 },   // STS k, Rr
};

// Decoder implementation functions

static DecodeStatus DecodeRdRr(MCInst *MI, uint16_t insn, uint64_t addr, const void *decoder)
{
    unsigned Rd = (insn >> 4) & 0x1F;
    unsigned Rr = ((insn >> 5) & 0x10) | (insn & 0x0F);
    
    MCOperand_CreateReg0(MI, AVR_REG_R0 + Rd);
    MCOperand_CreateReg0(MI, AVR_REG_R0 + Rr);
    
    return MCDisassembler_Success;
}

static DecodeStatus DecodeRdRrMul(MCInst *MI, uint16_t insn, uint64_t addr, const void *decoder)
{
    // For MULS: Rd and Rr are R16-R31 (bits 7:4 and 3:0 + 16)
    // For MULSU, FMUL, etc: Rd and Rr are R16-R23 (bits 6:4 and 2:0 + 16)
    unsigned opcode = MCInst_getOpcode(MI);
    
    if (opcode == AVR_INS_MULS) {
        unsigned Rd = ((insn >> 4) & 0x0F) + 16; // R16-R31
        unsigned Rr = (insn & 0x0F) + 16;        // R16-R31
        MCOperand_CreateReg0(MI, AVR_REG_R0 + Rd);
        MCOperand_CreateReg0(MI, AVR_REG_R0 + Rr);
    } else {
        unsigned Rd = ((insn >> 4) & 0x07) + 16; // R16-R23
        unsigned Rr = (insn & 0x07) + 16;        // R16-R23
        MCOperand_CreateReg0(MI, AVR_REG_R0 + Rd);
        MCOperand_CreateReg0(MI, AVR_REG_R0 + Rr);
    }
    
    return MCDisassembler_Success;
}

static DecodeStatus DecodeRdK8(MCInst *MI, uint16_t insn, uint64_t addr, const void *decoder)
{
    unsigned Rd = ((insn >> 4) & 0x0F) + 16; // Registers R16-R31 only
    unsigned K = ((insn >> 4) & 0xF0) | (insn & 0x0F);
    
    MCOperand_CreateReg0(MI, AVR_REG_R0 + Rd);
    MCOperand_CreateImm0(MI, K);
    
    return MCDisassembler_Success;
}

static DecodeStatus DecodeRd(MCInst *MI, uint16_t insn, uint64_t addr, const void *decoder)
{
    unsigned Rd = (insn >> 4) & 0x1F;
    
    MCOperand_CreateReg0(MI, AVR_REG_R0 + Rd);
    
    return MCDisassembler_Success;
}

static DecodeStatus DecodeBranch(MCInst *MI, uint16_t insn, uint64_t addr, const void *decoder)
{
    int16_t offset = SignExtend12(insn & 0xFFF); // Sign extend 12-bit offset
    int64_t target = addr + (offset * 2) + 2;    // PC-relative, word-addressed
    
    MCOperand_CreateImm0(MI, target);
    
    return MCDisassembler_Success;
}

static DecodeStatus DecodeBranchSR(MCInst *MI, uint16_t insn, uint64_t addr, const void *decoder)
{
    int8_t offset = SignExtend7((insn >> 3) & 0x7F);  // Sign extend 7-bit offset
    int64_t target = addr + (offset * 2) + 2;         // PC-relative, word-addressed
    unsigned bit = insn & 0x07;                       // Status bit
    
    // For generic BRBS/BRBC, add the bit operand
    unsigned opcode = MCInst_getOpcode(MI);
    if (opcode == AVR_INS_BRBS || opcode == AVR_INS_BRBC) {
        MCOperand_CreateImm0(MI, bit);
    }
    
    MCOperand_CreateImm0(MI, target);
    
    return MCDisassembler_Success;
}

static DecodeStatus DecodeIOBit(MCInst *MI, uint16_t insn, uint64_t addr, const void *decoder)
{
   unsigned A = (insn >> 3) & 0x1F;
   unsigned b = insn & 0x07;
   
   MCOperand_CreateImm0(MI, A);
   MCOperand_CreateImm0(MI, b);
   
   return MCDisassembler_Success;
}

static DecodeStatus DecodeRegBit(MCInst *MI, uint16_t insn, uint64_t addr, const void *decoder)
{
   unsigned Rd = (insn >> 4) & 0x1F;
   unsigned b = insn & 0x07;
   
   MCOperand_CreateReg0(MI, AVR_REG_R0 + Rd);
   MCOperand_CreateImm0(MI, b);
   
   return MCDisassembler_Success;
}

static DecodeStatus DecodeSkipBit(MCInst *MI, uint16_t insn, uint64_t addr, const void *decoder)
{
   unsigned Rr = (insn >> 4) & 0x1F;
   unsigned b = insn & 0x07;
   
   MCOperand_CreateReg0(MI, AVR_REG_R0 + Rr);
   MCOperand_CreateImm0(MI, b);
   
   return MCDisassembler_Success;
}

static DecodeStatus DecodeIOImm(MCInst *MI, uint16_t insn, uint64_t addr, const void *decoder)
{
   unsigned Rd = (insn >> 4) & 0x1F;
   unsigned A = ((insn >> 5) & 0x30) | (insn & 0x0F);
   
   MCOperand_CreateReg0(MI, AVR_REG_R0 + Rd);
   MCOperand_CreateImm0(MI, A);
   
   return MCDisassembler_Success;
}

static DecodeStatus DecodeIOOut(MCInst *MI, uint16_t insn, uint64_t addr, const void *decoder)
{
   unsigned Rr = (insn >> 4) & 0x1F;
   unsigned A = ((insn >> 5) & 0x30) | (insn & 0x0F);
   
   MCOperand_CreateImm0(MI, A);         // I/O address first
   MCOperand_CreateReg0(MI, AVR_REG_R0 + Rr);  // Register second
   
   return MCDisassembler_Success;
}

static DecodeStatus DecodeWordPair(MCInst *MI, uint16_t insn, uint64_t addr, const void *decoder)
{
   unsigned Rd = ((insn >> 4) & 0x03) * 2 + 24; // R24, R26, R28, R30
   unsigned K = ((insn >> 2) & 0x30) | (insn & 0x0F);
   
   MCOperand_CreateReg0(MI, AVR_REG_R0 + Rd);
   MCOperand_CreateImm0(MI, K);
   
   return MCDisassembler_Success;
}

static DecodeStatus DecodeIndirect(MCInst *MI, uint16_t insn, uint64_t addr, const void *decoder)
{
   unsigned Rd = (insn >> 4) & 0x1F;
   unsigned ptr = 0;
   avr_addressing_mode_t mode = AVR_AM_NORMAL;
   
   // Determine pointer register and addressing mode based on instruction bits
   switch (insn & 0x000F) {
   case 0x000C:        // X register
       ptr = AVR_REG_X;
       mode = AVR_AM_NORMAL;
       break;
   case 0x000D:        // X+ register
       ptr = AVR_REG_X;
       mode = AVR_AM_POST_INC;
       break;
   case 0x000E:        // -X register
       ptr = AVR_REG_X;
       mode = AVR_AM_PRE_DEC;
       break;
   case 0x0008:        // Y register
       ptr = AVR_REG_Y;
       mode = AVR_AM_NORMAL;
       break;
   case 0x0009:        // Y+ register
       ptr = AVR_REG_Y;
       mode = AVR_AM_POST_INC;
       break;
   case 0x000A:        // -Y register
       ptr = AVR_REG_Y;
       mode = AVR_AM_PRE_DEC;
       break;
   case 0x0000:        // Z register
       ptr = AVR_REG_Z;
       mode = AVR_AM_NORMAL;
       break;
   case 0x0001:        // Z+ register
       ptr = AVR_REG_Z;
       mode = AVR_AM_POST_INC;
       break;
   case 0x0002:        // -Z register
       ptr = AVR_REG_Z;
       mode = AVR_AM_PRE_DEC;
       break;
   case 0x0004:        // Z register for LPM
       ptr = AVR_REG_Z;
       mode = AVR_AM_NORMAL;
       break;
   case 0x0005:        // Z+ register for LPM
       ptr = AVR_REG_Z;
       mode = AVR_AM_POST_INC;
       break;
   default:
       return MCDisassembler_Fail;
   }
   
   // For ST instructions, register order is different
   unsigned opcode = MCInst_getOpcode(MI);
   if (opcode == AVR_INS_ST) {
       MCOperand_CreateReg0(MI, ptr);
       if (mode == AVR_AM_POST_INC) {
           MCOperand_CreateImm0(MI, 1);      // post-increment
       } else if (mode == AVR_AM_PRE_DEC) {
           MCOperand_CreateImm0(MI, -1);     // pre-decrement
       }
       MCOperand_CreateReg0(MI, AVR_REG_R0 + Rd);
   } else {
       MCOperand_CreateReg0(MI, AVR_REG_R0 + Rd);
       MCOperand_CreateReg0(MI, ptr);
       if (mode == AVR_AM_POST_INC) {
           MCOperand_CreateImm0(MI, 1);      // post-increment
       } else if (mode == AVR_AM_PRE_DEC) {
           MCOperand_CreateImm0(MI, -1);     // pre-decrement
       }
   }
   
   return MCDisassembler_Success;
}

static DecodeStatus DecodeIndirectDisp(MCInst *MI, uint16_t insn, uint64_t addr, const void *decoder)
{
   unsigned Rd = (insn >> 4) & 0x1F;
   unsigned q = ((insn >> 8) & 0x20) | ((insn >> 7) & 0x18) | (insn & 0x07);
   unsigned ptr = ((insn >> 3) & 0x01) ? AVR_REG_Z : AVR_REG_Y;
   
   // For STD instructions, operand order is different
   unsigned opcode = MCInst_getOpcode(MI);
   if (opcode == AVR_INS_STD) {
       MCOperand_CreateReg0(MI, ptr);
       MCOperand_CreateImm0(MI, q);
       MCOperand_CreateReg0(MI, AVR_REG_R0 + Rd);
   } else {
       MCOperand_CreateReg0(MI, AVR_REG_R0 + Rd);
       MCOperand_CreateReg0(MI, ptr);
       MCOperand_CreateImm0(MI, q);
   }
   
   return MCDisassembler_Success;
}

static DecodeStatus DecodeNoOperands(MCInst *MI, uint16_t insn, uint64_t addr, const void *decoder)
{
   // No operands to decode
   return MCDisassembler_Success;
}

static DecodeStatus DecodeStatusBit(MCInst *MI, uint16_t insn, uint64_t addr, const void *decoder)
{
   unsigned bit = (insn >> 4) & 0x07;
   
   MCOperand_CreateImm0(MI, bit);
   
   return MCDisassembler_Success;
}

static DecodeStatus DecodeJmp32(MCInst *MI, uint32_t insn, uint64_t addr, const void *decoder)
{
   // Extract 22-bit address from 32-bit instruction
   uint32_t k = ((insn >> 3) & 0x3E) | (insn & 0x01) | ((insn >> 16) & 0xFFFF00);
   k = (k << 1); // Convert to byte address
   
   MCOperand_CreateImm0(MI, k);
   
   return MCDisassembler_Success;
}

static DecodeStatus DecodeCall32(MCInst *MI, uint32_t insn, uint64_t addr, const void *decoder)
{
   // Extract 22-bit address from 32-bit instruction
   uint32_t k = ((insn >> 3) & 0x3E) | (insn & 0x01) | ((insn >> 16) & 0xFFFF00);
   k = (k << 1); // Convert to byte address
   
   MCOperand_CreateImm0(MI, k);
   
   return MCDisassembler_Success;
}

static DecodeStatus DecodeLds32(MCInst *MI, uint32_t insn, uint64_t addr, const void *decoder)
{
   unsigned Rd = (insn >> 4) & 0x1F;
   uint16_t k = insn >> 16; // 16-bit data space address
   
   MCOperand_CreateReg0(MI, AVR_REG_R0 + Rd);
   MCOperand_CreateImm0(MI, k);
   
   return MCDisassembler_Success;
}

static DecodeStatus DecodeSts32(MCInst *MI, uint32_t insn, uint64_t addr, const void *decoder)
{
   unsigned Rr = (insn >> 4) & 0x1F;
   uint16_t k = insn >> 16; // 16-bit data space address
   
   MCOperand_CreateImm0(MI, k);        // Address first
   MCOperand_CreateReg0(MI, AVR_REG_R0 + Rr);  // Register second
   
   return MCDisassembler_Success;
}

// Main 16-bit instruction decoder
DecodeStatus AVR_getInstruction16(MCInst *MI, uint16_t Insn, uint64_t Address, void *Decoder)
{
   for (size_t i = 0; i < ARR_SIZE(decode16_table); i++) {
       const avr_decode16_entry_t *entry = &decode16_table[i];
       
       if ((Insn & entry->mask) == entry->pattern) {
           MCInst_setOpcode(MI, entry->instruction);
           return entry->decoder(MI, Insn, Address, Decoder);
       }
   }
   
   return MCDisassembler_Fail;
}

// Main 32-bit instruction decoder
DecodeStatus AVR_getInstruction32(MCInst *MI, uint32_t Insn, uint64_t Address, void *Decoder)
{
   for (size_t i = 0; i < ARR_SIZE(decode32_table); i++) {
       const avr_decode32_entry_t *entry = &decode32_table[i];
       
       if ((Insn & entry->mask) == entry->pattern) {
           MCInst_setOpcode(MI, entry->instruction);
           return entry->decoder(MI, Insn, Address, Decoder);
       }
   }
   
   return MCDisassembler_Fail;
}

// Helper function to determine if instruction is 32-bit
bool AVR_is32BitInstruction(uint16_t firstWord)
{
   // 32-bit instructions: JMP, CALL, LDS, STS
   return ((firstWord & 0xFE0E) == 0x940C) ||  // JMP
          ((firstWord & 0xFE0E) == 0x940E) ||  // CALL
          ((firstWord & 0xFE0F) == 0x9000) ||  // LDS
          ((firstWord & 0xFE0F) == 0x9200);    // STS
}

#endif