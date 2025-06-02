/* Capstone Disassembly Engine, http://www.capstone-engine.org */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2022, */
/* Rot127 <unisono@quyllur.org> 2022-2023 */
/* VoltagedDebunked <rusindanilo@gmail.com> 2025 */

#ifndef CS_AVRDISASSEMBLER_H
#define CS_AVRDISASSEMBLER_H

#include "../../MCDisassembler.h"
#include "../../MCInst.h"

bool AVR_getInstruction(csh ud, const uint8_t *code, size_t code_len,
                       MCInst *instr, uint16_t *size, uint64_t address,
                       void *info);

// Internal decoder functions
DecodeStatus AVR_getInstruction16(MCInst *MI, uint16_t Insn, uint64_t Address, void *Decoder);
DecodeStatus AVR_getInstruction32(MCInst *MI, uint32_t Insn, uint64_t Address, void *Decoder);

#endif