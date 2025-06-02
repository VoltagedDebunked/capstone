/* Capstone Disassembly Engine, http://www.capstone-engine.org */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2022, */
/* Rot127 <unisono@quyllur.org> 2022-2023 */
/* VoltagedDebunked <rusindanilo@gmail.com> 2025 */

#ifndef CS_AVRMAPPING_H
#define CS_AVRMAPPING_H

#include "../../cs_priv.h"

const char *AVR_reg_name(csh handle, unsigned int reg);
const char *AVR_insn_name(csh handle, unsigned int insn);
const char *AVR_group_name(csh handle, unsigned int group);

void AVR_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id);
void AVR_reg_access(const cs_insn *insn, cs_regs regs_read, uint8_t *regs_read_count,
                   cs_regs regs_write, uint8_t *regs_write_count);

#endif