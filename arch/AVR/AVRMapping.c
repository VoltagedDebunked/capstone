/* Capstone Disassembly Engine, http://www.capstone-engine.org */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2022, */
/* Rot127 <unisono@quyllur.org> 2022-2023 */
/* VoltagedDebunked <rusindanilo@gmail.com> 2025 */

#include <stdio.h>
#include <string.h>

#include "../../cs_priv.h"
#include "../../utils.h"
#include "AVRMapping.h"

#ifdef CAPSTONE_HAS_AVR

typedef struct name_map {
    unsigned int id;
    const char *name;
} name_map;

// Helper function to find name by id in name_map array
static const char *id2name(const name_map *map, size_t map_size, unsigned int id)
{
    for (size_t i = 0; i < map_size; i++) {
        if (map[i].id == id) {
            return map[i].name;
        }
    }
    return NULL;  // Return NULL for unknown IDs instead of crashing
}

static const name_map reg_name_maps[] = {
    { AVR_REG_INVALID, NULL },
    { AVR_REG_R0, "r0" },
    { AVR_REG_R1, "r1" },
    { AVR_REG_R2, "r2" },
    { AVR_REG_R3, "r3" },
    { AVR_REG_R4, "r4" },
    { AVR_REG_R5, "r5" },
    { AVR_REG_R6, "r6" },
    { AVR_REG_R7, "r7" },
    { AVR_REG_R8, "r8" },
    { AVR_REG_R9, "r9" },
    { AVR_REG_R10, "r10" },
    { AVR_REG_R11, "r11" },
    { AVR_REG_R12, "r12" },
    { AVR_REG_R13, "r13" },
    { AVR_REG_R14, "r14" },
    { AVR_REG_R15, "r15" },
    { AVR_REG_R16, "r16" },
    { AVR_REG_R17, "r17" },
    { AVR_REG_R18, "r18" },
    { AVR_REG_R19, "r19" },
    { AVR_REG_R20, "r20" },
    { AVR_REG_R21, "r21" },
    { AVR_REG_R22, "r22" },
    { AVR_REG_R23, "r23" },
    { AVR_REG_R24, "r24" },
    { AVR_REG_R25, "r25" },
    { AVR_REG_R26, "r26" },
    { AVR_REG_R27, "r27" },
    { AVR_REG_R28, "r28" },
    { AVR_REG_R29, "r29" },
    { AVR_REG_R30, "r30" },
    { AVR_REG_R31, "r31" },
    { AVR_REG_X, "X" },
    { AVR_REG_Y, "Y" },
    { AVR_REG_Z, "Z" },
    { AVR_REG_SP, "SP" },
    { AVR_REG_PC, "PC" },
    { AVR_REG_SREG, "SREG" },
};

static const name_map insn_name_maps[] = {
    { AVR_INS_INVALID, NULL },
    { AVR_INS_ADD, "add" },
    { AVR_INS_ADC, "adc" },
    { AVR_INS_ADIW, "adiw" },
    { AVR_INS_SUB, "sub" },
    { AVR_INS_SUBI, "subi" },
    { AVR_INS_SBC, "sbc" },
    { AVR_INS_SBCI, "sbci" },
    { AVR_INS_SBIW, "sbiw" },
    { AVR_INS_AND, "and" },
    { AVR_INS_ANDI, "andi" },
    { AVR_INS_OR, "or" },
    { AVR_INS_ORI, "ori" },
    { AVR_INS_EOR, "eor" },
    { AVR_INS_COM, "com" },
    { AVR_INS_NEG, "neg" },
    { AVR_INS_SBR, "sbr" },
    { AVR_INS_CBR, "cbr" },
    { AVR_INS_INC, "inc" },
    { AVR_INS_DEC, "dec" },
    { AVR_INS_TST, "tst" },
    { AVR_INS_CLR, "clr" },
    { AVR_INS_SER, "ser" },
    { AVR_INS_MUL, "mul" },
    { AVR_INS_MULS, "muls" },
    { AVR_INS_MULSU, "mulsu" },
    { AVR_INS_FMUL, "fmul" },
    { AVR_INS_FMULS, "fmuls" },
    { AVR_INS_FMULSU, "fmulsu" },
    { AVR_INS_RJMP, "rjmp" },
    { AVR_INS_IJMP, "ijmp" },
    { AVR_INS_EIJMP, "eijmp" },
    { AVR_INS_JMP, "jmp" },
    { AVR_INS_RCALL, "rcall" },
    { AVR_INS_ICALL, "icall" },
    { AVR_INS_EICALL, "eicall" },
    { AVR_INS_CALL, "call" },
    { AVR_INS_RET, "ret" },
    { AVR_INS_RETI, "reti" },
    { AVR_INS_CPSE, "cpse" },
    { AVR_INS_CP, "cp" },
    { AVR_INS_CPC, "cpc" },
    { AVR_INS_CPI, "cpi" },
    { AVR_INS_SBRC, "sbrc" },
    { AVR_INS_SBRS, "sbrs" },
    { AVR_INS_SBIC, "sbic" },
    { AVR_INS_SBIS, "sbis" },
    { AVR_INS_BRBS, "brbs" },
    { AVR_INS_BRBC, "brbc" },
    { AVR_INS_BREQ, "breq" },
    { AVR_INS_BRNE, "brne" },
    { AVR_INS_BRCS, "brcs" },
    { AVR_INS_BRCC, "brcc" },
    { AVR_INS_BRSH, "brsh" },
    { AVR_INS_BRLO, "brlo" },
    { AVR_INS_BRMI, "brmi" },
    { AVR_INS_BRPL, "brpl" },
    { AVR_INS_BRGE, "brge" },
    { AVR_INS_BRLT, "brlt" },
    { AVR_INS_BRHS, "brhs" },
    { AVR_INS_BRHC, "brhc" },
    { AVR_INS_BRTS, "brts" },
    { AVR_INS_BRTC, "brtc" },
    { AVR_INS_BRVS, "brvs" },
    { AVR_INS_BRVC, "brvc" },
    { AVR_INS_BRIE, "brie" },
    { AVR_INS_BRID, "brid" },
    { AVR_INS_MOV, "mov" },
    { AVR_INS_MOVW, "movw" },
    { AVR_INS_LDI, "ldi" },
    { AVR_INS_LD, "ld" },
    { AVR_INS_LDD, "ldd" },
    { AVR_INS_LDS, "lds" },
    { AVR_INS_ST, "st" },
    { AVR_INS_STD, "std" },
    { AVR_INS_STS, "sts" },
    { AVR_INS_LPM, "lpm" },
    { AVR_INS_ELPM, "elpm" },
    { AVR_INS_SPM, "spm" },
    { AVR_INS_IN, "in" },
    { AVR_INS_OUT, "out" },
    { AVR_INS_PUSH, "push" },
    { AVR_INS_POP, "pop" },
    { AVR_INS_SBI, "sbi" },
    { AVR_INS_CBI, "cbi" },
    { AVR_INS_LSL, "lsl" },
    { AVR_INS_LSR, "lsr" },
    { AVR_INS_ROL, "rol" },
    { AVR_INS_ROR, "ror" },
    { AVR_INS_ASR, "asr" },
    { AVR_INS_SWAP, "swap" },
    { AVR_INS_BSET, "bset" },
    { AVR_INS_BCLR, "bclr" },
    { AVR_INS_BST, "bst" },
    { AVR_INS_BLD, "bld" },
    { AVR_INS_SEC, "sec" },
    { AVR_INS_CLC, "clc" },
    { AVR_INS_SEN, "sen" },
    { AVR_INS_CLN, "cln" },
    { AVR_INS_SEZ, "sez" },
    { AVR_INS_CLZ, "clz" },
    { AVR_INS_SEI, "sei" },
    { AVR_INS_CLI, "cli" },
    { AVR_INS_SES, "ses" },
    { AVR_INS_CLS, "cls" },
    { AVR_INS_SEV, "sev" },
    { AVR_INS_CLV, "clv" },
    { AVR_INS_SET, "set" },
    { AVR_INS_CLT, "clt" },
    { AVR_INS_SEH, "seh" },
    { AVR_INS_CLH, "clh" },
    { AVR_INS_NOP, "nop" },
    { AVR_INS_SLEEP, "sleep" },
    { AVR_INS_WDR, "wdr" },
    { AVR_INS_BREAK, "break" },
};

static const name_map group_name_maps[] = {
    { AVR_GRP_INVALID, NULL },
    { AVR_GRP_JUMP, "jump" },
    { AVR_GRP_CALL, "call" },
    { AVR_GRP_RET, "ret" },
    { AVR_GRP_INT, "int" },
    { AVR_GRP_IRET, "iret" },
    { AVR_GRP_PRIVILEGE, "privilege" },
    { AVR_GRP_BRANCH_RELATIVE, "branch_relative" },
    { AVR_GRP_ARITHMETIC, "arithmetic" },
    { AVR_GRP_LOGIC, "logic" },
    { AVR_GRP_DATA_TRANSFER, "data_transfer" },
    { AVR_GRP_BIT_TEST, "bit_test" },
    { AVR_GRP_MCU_CONTROL, "mcu_control" },
};

const char *AVR_reg_name(csh handle, unsigned int reg)
{
    if (reg == 0 || reg >= AVR_REG_ENDING) {
        return NULL;  // Invalid register ID
    }
    
    const char *name = id2name(reg_name_maps, sizeof(reg_name_maps)/sizeof(reg_name_maps[0]), reg);
    if (!name) {
        // Debug: print what register ID we couldn't find
        // You can remove this later
        static char unknown_reg[32];
        snprintf(unknown_reg, sizeof(unknown_reg), "REG_%u", reg);
        return unknown_reg;
    }
    return name;
}

const char *AVR_insn_name(csh handle, unsigned int insn)
{
    return id2name(insn_name_maps, sizeof(insn_name_maps)/sizeof(insn_name_maps[0]), insn);
}

const char *AVR_group_name(csh handle, unsigned int group)
{
    return id2name(group_name_maps, sizeof(group_name_maps)/sizeof(group_name_maps[0]), group);
}

void AVR_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id)
{
    // Set instruction ID
    insn->id = id;
    
    // Safety check for detail structure
    if (!insn->detail) {
        return;
    }
    
    // Set instruction groups based on the instruction type
    switch (id) {
    case AVR_INS_RJMP:
    case AVR_INS_IJMP:
    case AVR_INS_EIJMP:
    case AVR_INS_JMP:
        if (insn->detail->groups_count < 8) {
            insn->detail->groups[insn->detail->groups_count++] = AVR_GRP_JUMP;
        }
        break;
        
    case AVR_INS_RCALL:
    case AVR_INS_ICALL:
    case AVR_INS_EICALL:
    case AVR_INS_CALL:
        if (insn->detail->groups_count < 8) {
            insn->detail->groups[insn->detail->groups_count++] = AVR_GRP_CALL;
        }
        break;
        
    case AVR_INS_RET:
        if (insn->detail->groups_count < 8) {
            insn->detail->groups[insn->detail->groups_count++] = AVR_GRP_RET;
        }
        break;
        
    case AVR_INS_RETI:
        if (insn->detail->groups_count < 7) {
            insn->detail->groups[insn->detail->groups_count++] = AVR_GRP_IRET;
            insn->detail->groups[insn->detail->groups_count++] = AVR_GRP_INT;
        }
        break;
        
    case AVR_INS_SEI:
    case AVR_INS_CLI:
        if (insn->detail->groups_count < 8) {
            insn->detail->groups[insn->detail->groups_count++] = AVR_GRP_INT;
        }
        break;
        
    case AVR_INS_BREQ:
    case AVR_INS_BRNE:
    case AVR_INS_BRCS:
    case AVR_INS_BRCC:
    case AVR_INS_BRSH:
    case AVR_INS_BRLO:
    case AVR_INS_BRMI:
    case AVR_INS_BRPL:
    case AVR_INS_BRGE:
    case AVR_INS_BRLT:
    case AVR_INS_BRHS:
    case AVR_INS_BRHC:
    case AVR_INS_BRTS:
    case AVR_INS_BRTC:
    case AVR_INS_BRVS:
    case AVR_INS_BRVC:
    case AVR_INS_BRIE:
    case AVR_INS_BRID:
    case AVR_INS_BRBS:
    case AVR_INS_BRBC:
        if (insn->detail->groups_count < 8) {
            insn->detail->groups[insn->detail->groups_count++] = AVR_GRP_BRANCH_RELATIVE;
        }
        break;
        
    case AVR_INS_ADD:
    case AVR_INS_ADC:
    case AVR_INS_ADIW:
    case AVR_INS_SUB:
    case AVR_INS_SUBI:
    case AVR_INS_SBC:
    case AVR_INS_SBCI:
    case AVR_INS_SBIW:
    case AVR_INS_INC:
    case AVR_INS_DEC:
    case AVR_INS_MUL:
    case AVR_INS_MULS:
    case AVR_INS_MULSU:
    case AVR_INS_FMUL:
    case AVR_INS_FMULS:
    case AVR_INS_FMULSU:
    case AVR_INS_NEG:
        if (insn->detail->groups_count < 8) {
            insn->detail->groups[insn->detail->groups_count++] = AVR_GRP_ARITHMETIC;
        }
        break;
        
    case AVR_INS_AND:
    case AVR_INS_ANDI:
    case AVR_INS_OR:
    case AVR_INS_ORI:
    case AVR_INS_EOR:
    case AVR_INS_COM:
    case AVR_INS_SBR:
    case AVR_INS_CBR:
    case AVR_INS_TST:
    case AVR_INS_CLR:
    case AVR_INS_SER:
    case AVR_INS_LSL:
    case AVR_INS_LSR:
    case AVR_INS_ROL:
    case AVR_INS_ROR:
    case AVR_INS_ASR:
    case AVR_INS_SWAP:
        if (insn->detail->groups_count < 8) {
            insn->detail->groups[insn->detail->groups_count++] = AVR_GRP_LOGIC;
        }
        break;
        
    case AVR_INS_MOV:
    case AVR_INS_MOVW:
    case AVR_INS_LDI:
    case AVR_INS_LD:
    case AVR_INS_LDD:
    case AVR_INS_LDS:
    case AVR_INS_ST:
    case AVR_INS_STD:
    case AVR_INS_STS:
    case AVR_INS_LPM:
    case AVR_INS_ELPM:
    case AVR_INS_SPM:
    case AVR_INS_IN:
    case AVR_INS_OUT:
    case AVR_INS_PUSH:
    case AVR_INS_POP:
        if (insn->detail->groups_count < 8) {
            insn->detail->groups[insn->detail->groups_count++] = AVR_GRP_DATA_TRANSFER;
        }
        break;
        
    case AVR_INS_SBRC:
    case AVR_INS_SBRS:
    case AVR_INS_SBIC:
    case AVR_INS_SBIS:
    case AVR_INS_SBI:
    case AVR_INS_CBI:
    case AVR_INS_BST:
    case AVR_INS_BLD:
    case AVR_INS_BSET:
    case AVR_INS_BCLR:
    case AVR_INS_SEC:
    case AVR_INS_CLC:
    case AVR_INS_SEN:
    case AVR_INS_CLN:
    case AVR_INS_SEZ:
    case AVR_INS_CLZ:
    case AVR_INS_SES:
    case AVR_INS_CLS:
    case AVR_INS_SEV:
    case AVR_INS_CLV:
    case AVR_INS_SET:
    case AVR_INS_CLT:
    case AVR_INS_SEH:
    case AVR_INS_CLH:
        if (insn->detail->groups_count < 8) {
            insn->detail->groups[insn->detail->groups_count++] = AVR_GRP_BIT_TEST;
        }
        break;
        
    case AVR_INS_NOP:
    case AVR_INS_SLEEP:
    case AVR_INS_WDR:
    case AVR_INS_BREAK:
        if (insn->detail->groups_count < 8) {
            insn->detail->groups[insn->detail->groups_count++] = AVR_GRP_MCU_CONTROL;
        }
        break;
        
    case AVR_INS_CP:
    case AVR_INS_CPC:
    case AVR_INS_CPI:
    case AVR_INS_CPSE:
        // These don't belong to any specific group, they're comparison ops
        break;
    }
}

// Get register access info
void AVR_reg_access(const cs_insn *insn, cs_regs regs_read, uint8_t *regs_read_count,
                   cs_regs regs_write, uint8_t *regs_write_count)
{
    uint8_t read_count = 0;
    uint8_t write_count = 0;
    
    if (!insn->detail)
        return;
    
    const cs_avr *avr = &insn->detail->avr;
    
    // Basic register access patterns based on instruction type
    switch (insn->id) {
    case AVR_INS_ADD:
    case AVR_INS_ADC:
    case AVR_INS_SUB:
    case AVR_INS_SBC:
    case AVR_INS_AND:
    case AVR_INS_OR:
    case AVR_INS_EOR:
    case AVR_INS_CP:
    case AVR_INS_CPC:
        // Two register operations: Rd = Rd op Rr
        if (avr->op_count >= 2) {
            regs_read[read_count++] = avr->operands[0].reg;
            regs_read[read_count++] = avr->operands[1].reg;
            regs_write[write_count++] = avr->operands[0].reg;
        }
        regs_write[write_count++] = AVR_REG_SREG;
        break;
        
    case AVR_INS_SUBI:
    case AVR_INS_SBCI:
    case AVR_INS_ANDI:
    case AVR_INS_ORI:
    case AVR_INS_CPI:
        // Register + immediate operations: Rd = Rd op K
        if (avr->op_count >= 1) {
            regs_read[read_count++] = avr->operands[0].reg;
            regs_write[write_count++] = avr->operands[0].reg;
        }
        regs_write[write_count++] = AVR_REG_SREG;
        break;
        
    case AVR_INS_MOV:
    case AVR_INS_LDI:
        // Move operations: Rd = Rr or Rd = K
        if (avr->op_count >= 2) {
            if (avr->operands[1].type == AVR_OP_REG)
                regs_read[read_count++] = avr->operands[1].reg;
            regs_write[write_count++] = avr->operands[0].reg;
        }
        break;
        
    case AVR_INS_LD:
    case AVR_INS_LDD:
        // Load operations: Rd = [Rr+k]
        if (avr->op_count >= 2) {
            regs_read[read_count++] = avr->operands[1].reg;
            regs_write[write_count++] = avr->operands[0].reg;
        }
        break;
        
    case AVR_INS_ST:
    case AVR_INS_STD:
        // Store operations: [Rr+k] = Rd
        if (avr->op_count >= 2) {
            regs_read[read_count++] = avr->operands[0].reg;
            regs_read[read_count++] = avr->operands[1].reg;
        }
        break;
        
    case AVR_INS_PUSH:
        // Push: SP--, [SP] = Rr
        if (avr->op_count >= 1) {
            regs_read[read_count++] = avr->operands[0].reg;
            regs_read[read_count++] = AVR_REG_SP;
            regs_write[write_count++] = AVR_REG_SP;
        }
        break;
        
    case AVR_INS_POP:
        // Pop: Rd = [SP], SP++
        if (avr->op_count >= 1) {
            regs_read[read_count++] = AVR_REG_SP;
            regs_write[write_count++] = avr->operands[0].reg;
            regs_write[write_count++] = AVR_REG_SP;
        }
        break;
        
    case AVR_INS_CALL:
    case AVR_INS_RCALL:
    case AVR_INS_ICALL:
    case AVR_INS_EICALL:
        // Call instructions modify stack pointer and PC
        regs_read[read_count++] = AVR_REG_SP;
        regs_write[write_count++] = AVR_REG_SP;
        regs_write[write_count++] = AVR_REG_PC;
        if (insn->id == AVR_INS_ICALL)
            regs_read[read_count++] = AVR_REG_Z;
        break;
        
    case AVR_INS_RET:
    case AVR_INS_RETI:
        // Return instructions modify stack pointer and PC
        regs_read[read_count++] = AVR_REG_SP;
        regs_write[write_count++] = AVR_REG_SP;
        regs_write[write_count++] = AVR_REG_PC;
        if (insn->id == AVR_INS_RETI)
            regs_write[write_count++] = AVR_REG_SREG;
        break;
        
    case AVR_INS_SEI:
    case AVR_INS_CLI:
    case AVR_INS_SEC:
    case AVR_INS_CLC:
    case AVR_INS_SEN:
    case AVR_INS_CLN:
    case AVR_INS_SEZ:
    case AVR_INS_CLZ:
    case AVR_INS_SES:
    case AVR_INS_CLS:
    case AVR_INS_SEV:
    case AVR_INS_CLV:
    case AVR_INS_SET:
    case AVR_INS_CLT:
    case AVR_INS_SEH:
    case AVR_INS_CLH:
        // Flag operations modify SREG
        regs_write[write_count++] = AVR_REG_SREG;
        break;
    }
    
    *regs_read_count = read_count;
    *regs_write_count = write_count;
}

#endif