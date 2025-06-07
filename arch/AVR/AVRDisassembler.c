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
#include "AVRDisassembler.h"
#include "AVRMapping.h"

#ifdef CAPSTONE_HAS_AVR

// Register decoder helpers
static unsigned __attribute__((unused))DecodeGPR8RegisterClass(MCInst *Inst, unsigned RegNo,
                                       uint64_t Address, const void *Decoder)
{
    if (RegNo > 31)
        return MCDisassembler_Fail;
    
    unsigned Register = AVR_REG_R0 + RegNo;
    MCOperand_CreateReg0(Inst, Register);
    return MCDisassembler_Success;
}

static unsigned __attribute__((unused)) DecodeGPR16RegisterClass(MCInst *Inst, unsigned RegNo,
                                        uint64_t Address, const void *Decoder)
{
    if (RegNo > 15)
        return MCDisassembler_Fail;
    
    unsigned Register = AVR_REG_R16 + RegNo;
    MCOperand_CreateReg0(Inst, Register);
    return MCDisassembler_Success;
}

static unsigned DecodePTRREGSRegisterClass(MCInst *Inst, unsigned RegNo,
                                          uint64_t Address, const void *Decoder)
{
    switch (RegNo) {
    case 0: MCOperand_CreateReg0(Inst, AVR_REG_X); break;
    case 1: MCOperand_CreateReg0(Inst, AVR_REG_Y); break;
    case 2: MCOperand_CreateReg0(Inst, AVR_REG_Z); break;
    default: return MCDisassembler_Fail;
    }
    return MCDisassembler_Success;
}

// Immediate decoder helpers
static unsigned __attribute__((unused)) DecodeImm8(MCInst *Inst, unsigned Imm,
                          uint64_t Address, const void *Decoder)
{
    MCOperand_CreateImm0(Inst, Imm);
    return MCDisassembler_Success;
}

static unsigned __attribute__((unused)) DecodeImm16(MCInst *Inst, unsigned Imm,
                           uint64_t Address, const void *Decoder)
{
    MCOperand_CreateImm0(Inst, Imm);
    return MCDisassembler_Success;
}

static unsigned __attribute__((unused)) DecodeRelativeImm7(MCInst *Inst, unsigned Imm,
                                  uint64_t Address, const void *Decoder)
{
    // Sign extend 7-bit immediate
    if (Imm & 0x40)
        Imm |= 0xFFFFFF80;
    
    MCOperand_CreateImm0(Inst, Imm);
    return MCDisassembler_Success;
}

static unsigned __attribute__((unused)) DecodeRelativeImm12(MCInst *Inst, unsigned Imm,
                                   uint64_t Address, const void *Decoder)
{
    // Sign extend 12-bit immediate
    if (Imm & 0x800)
        Imm |= 0xFFFFF000;
    
    MCOperand_CreateImm0(Inst, Imm);
    return MCDisassembler_Success;
}

// Memory operand decoders
static unsigned __attribute__((unused)) DecodeMemri(MCInst *Inst, unsigned Insn,
                           uint64_t Address, const void *Decoder)
{
    unsigned Base = (Insn >> 5) & 0x3;
    unsigned Offset = Insn & 0x1F;
    
    if (DecodePTRREGSRegisterClass(Inst, Base, Address, Decoder) == MCDisassembler_Fail)
        return MCDisassembler_Fail;
    
    MCOperand_CreateImm0(Inst, Offset);
    return MCDisassembler_Success;
}

// I/O register decoder
static unsigned __attribute__((unused)) DecodeIORegister(MCInst *Inst, unsigned RegNo,
                                uint64_t Address, const void *Decoder)
{
    if (RegNo >= AVR_REG_ENDING)
        return MCDisassembler_Fail;
    
    MCOperand_CreateImm0(Inst, RegNo);
    return MCDisassembler_Success;
}

// Main disassembler function
static DecodeStatus getInstruction(MCInst *MI, uint16_t *Size,
                                  const uint8_t *Bytes, size_t BytesLen,
                                  uint64_t Address, void *DisAsm)
{
    if (BytesLen < 2) {
        *Size = 0;
        return MCDisassembler_Fail;
    }
    
    uint16_t Insn = (Bytes[1] << 8) | Bytes[0];
    *Size = 2;
    
    // Check for 32-bit instructions (JMP, CALL, LDS, STS)
    if ((Insn & 0xFE0E) == 0x940C || // JMP
        (Insn & 0xFE0E) == 0x940E || // CALL
        (Insn & 0xFE0F) == 0x9000 || // LDS
        (Insn & 0xFE0F) == 0x9200) { // STS
        if (BytesLen < 4) {
            *Size = 0;
            return MCDisassembler_Fail;
        }
        *Size = 4;
        uint16_t Insn2 = (Bytes[3] << 8) | Bytes[2];
        uint32_t FullInsn = (Insn2 << 16) | Insn;
        return AVR_getInstruction32(MI, FullInsn, Address, DisAsm);
    }
    
    return AVR_getInstruction16(MI, Insn, Address, DisAsm);
}

bool AVR_getInstruction(csh ud, const uint8_t *code, size_t code_len,
                       MCInst *instr, uint16_t *size, uint64_t address,
                       void *info)
{
    DecodeStatus status = getInstruction(instr, size, code, code_len, address, info);
    return status != MCDisassembler_Fail;
}

#endif