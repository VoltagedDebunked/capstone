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