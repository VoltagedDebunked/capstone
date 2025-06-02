/* Capstone Disassembly Engine, http://www.capstone-engine.org */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2022, */
/* Rot127 <unisono@quyllur.org> 2022-2023 */
/* VoltagedDebunked <rusindanilo@gmail.com> 2025 */

#ifndef CS_AVRINSTPRINTER_H
#define CS_AVRINSTPRINTER_H

#include "../../MCInst.h"
#include "../../SStream.h"

void AVR_printInst(MCInst *MI, SStream *O, void *PrinterInfo);

#endif