/* Capstone Disassembly Engine, http://www.capstone-engine.org */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2022, */
/* Rot127 <unisono@quyllur.org> 2022-2023 */
/* VoltagedDebunked <rusindanilo@gmail.com> 2025 */

#ifndef CAPSTONE_AVR_H
#define CAPSTONE_AVR_H

#ifdef __cplusplus
extern "C" {
#endif

#include "platform.h"

#ifdef _MSC_VER
#pragma warning(disable:4201)
#pragma warning(disable:4214)
#endif

// AVR registers
typedef enum avr_reg {
    AVR_REG_INVALID = 0,
    
    // General purpose registers R0-R31
    AVR_REG_R0, AVR_REG_R1, AVR_REG_R2, AVR_REG_R3,
    AVR_REG_R4, AVR_REG_R5, AVR_REG_R6, AVR_REG_R7,
    AVR_REG_R8, AVR_REG_R9, AVR_REG_R10, AVR_REG_R11,
    AVR_REG_R12, AVR_REG_R13, AVR_REG_R14, AVR_REG_R15,
    AVR_REG_R16, AVR_REG_R17, AVR_REG_R18, AVR_REG_R19,
    AVR_REG_R20, AVR_REG_R21, AVR_REG_R22, AVR_REG_R23,
    AVR_REG_R24, AVR_REG_R25, AVR_REG_R26, AVR_REG_R27,
    AVR_REG_R28, AVR_REG_R29, AVR_REG_R30, AVR_REG_R31,
    
    // Pointer registers (these get unique values)
    AVR_REG_X, AVR_REG_Y, AVR_REG_Z,
    
    // Special registers
    AVR_REG_SP, AVR_REG_PC, AVR_REG_SREG,
    
    AVR_REG_ENDING
} avr_reg;

// AVR instruction groups
typedef enum avr_group_type {
    AVR_GRP_INVALID = 0,
    
    // Generic groups
    AVR_GRP_JUMP,     // All jump instructions
    AVR_GRP_CALL,     // All call instructions 
    AVR_GRP_RET,      // All return instructions
    AVR_GRP_INT,      // All interrupt instructions
    AVR_GRP_IRET,     // All interrupt return instructions
    AVR_GRP_PRIVILEGE,// All privileged instructions
    AVR_GRP_BRANCH_RELATIVE, // All relative branching instructions
    
    // Architecture-specific groups
    AVR_GRP_ARITHMETIC = 128,   // Arithmetic operations
    AVR_GRP_LOGIC,        // Logic operations
    AVR_GRP_DATA_TRANSFER,// Data transfer operations
    AVR_GRP_BIT_TEST,     // Bit test operations
    AVR_GRP_MCU_CONTROL,  // MCU control operations
    
    AVR_GRP_ENDING
} avr_group_type;

// AVR instruction IDs
typedef enum avr_insn {
    AVR_INS_INVALID = 0,
    
    // Arithmetic and Logic Instructions
    AVR_INS_ADD,     // Add without Carry
    AVR_INS_ADC,     // Add with Carry
    AVR_INS_ADIW,    // Add Immediate to Word
    AVR_INS_SUB,     // Subtract without Carry
    AVR_INS_SUBI,    // Subtract Immediate
    AVR_INS_SBC,     // Subtract with Carry
    AVR_INS_SBCI,    // Subtract Immediate with Carry
    AVR_INS_SBIW,    // Subtract Immediate from Word
    AVR_INS_AND,     // Logical AND
    AVR_INS_ANDI,    // Logical AND with Immediate
    AVR_INS_OR,      // Logical OR
    AVR_INS_ORI,     // Logical OR with Immediate
    AVR_INS_EOR,     // Exclusive OR
    AVR_INS_COM,     // One's Complement
    AVR_INS_NEG,     // Two's Complement
    AVR_INS_SBR,     // Set Bit(s) in Register
    AVR_INS_CBR,     // Clear Bit(s) in Register
    AVR_INS_INC,     // Increment
    AVR_INS_DEC,     // Decrement
    AVR_INS_TST,     // Test for Zero or Minus
    AVR_INS_CLR,     // Clear Register
    AVR_INS_SER,     // Set Register
    AVR_INS_MUL,     // Multiply Unsigned
    AVR_INS_MULS,    // Multiply Signed
    AVR_INS_MULSU,   // Multiply Signed with Unsigned
    AVR_INS_FMUL,    // Fractional Multiply Unsigned
    AVR_INS_FMULS,   // Fractional Multiply Signed
    AVR_INS_FMULSU,  // Fractional Multiply Signed with Unsigned
    
    // Branch Instructions
    AVR_INS_RJMP,    // Relative Jump
    AVR_INS_IJMP,    // Indirect Jump to (Z)
    AVR_INS_EIJMP,   // Extended Indirect Jump to (Z)
    AVR_INS_JMP,     // Jump
    AVR_INS_RCALL,   // Relative Subroutine Call
    AVR_INS_ICALL,   // Indirect Call to (Z)
    AVR_INS_EICALL,  // Extended Indirect Call to (Z)
    AVR_INS_CALL,    // Subroutine Call
    AVR_INS_RET,     // Subroutine Return
    AVR_INS_RETI,    // Interrupt Return
    AVR_INS_CPSE,    // Compare, Skip if Equal
    AVR_INS_CP,      // Compare
    AVR_INS_CPC,     // Compare with Carry
    AVR_INS_CPI,     // Compare Register with Immediate
    AVR_INS_SBRC,    // Skip if Bit in Register Cleared
    AVR_INS_SBRS,    // Skip if Bit in Register Set
    AVR_INS_SBIC,    // Skip if Bit in I/O Register Cleared
    AVR_INS_SBIS,    // Skip if Bit in I/O Register Set
    AVR_INS_BRBS,    // Branch if Status Flag Set
    AVR_INS_BRBC,    // Branch if Status Flag Cleared
    AVR_INS_BREQ,    // Branch if Equal
    AVR_INS_BRNE,    // Branch if Not Equal
    AVR_INS_BRCS,    // Branch if Carry Set
    AVR_INS_BRCC,    // Branch if Carry Cleared
    AVR_INS_BRSH,    // Branch if Same or Higher
    AVR_INS_BRLO,    // Branch if Lower
    AVR_INS_BRMI,    // Branch if Minus
    AVR_INS_BRPL,    // Branch if Plus
    AVR_INS_BRGE,    // Branch if Greater or Equal, Signed
    AVR_INS_BRLT,    // Branch if Less Than Zero, Signed
    AVR_INS_BRHS,    // Branch if Half Carry Flag Set
    AVR_INS_BRHC,    // Branch if Half Carry Flag Cleared
    AVR_INS_BRTS,    // Branch if T Flag Set
    AVR_INS_BRTC,    // Branch if T Flag Cleared
    AVR_INS_BRVS,    // Branch if Overflow Flag is Set
    AVR_INS_BRVC,    // Branch if Overflow Flag is Cleared
    AVR_INS_BRIE,    // Branch if Interrupt Enabled
    AVR_INS_BRID,    // Branch if Interrupt Disabled
    
    // Data Transfer Instructions
    AVR_INS_MOV,     // Copy Register
    AVR_INS_MOVW,    // Copy Register Word
    AVR_INS_LDI,     // Load Immediate
    AVR_INS_LD,      // Load Indirect
    AVR_INS_LDD,     // Load Indirect with Displacement
    AVR_INS_LDS,     // Load Direct from SRAM
    AVR_INS_ST,      // Store Indirect
    AVR_INS_STD,     // Store Indirect with Displacement
    AVR_INS_STS,     // Store Direct to SRAM
    AVR_INS_LPM,     // Load Program Memory
    AVR_INS_ELPM,    // Extended Load Program Memory
    AVR_INS_SPM,     // Store Program Memory
    AVR_INS_IN,      // In From I/O Location
    AVR_INS_OUT,     // Out To I/O Location
    AVR_INS_PUSH,    // Push Register on Stack
    AVR_INS_POP,     // Pop Register from Stack
    
    // Bit and Bit-test Instructions
    AVR_INS_SBI,     // Set Bit in I/O Register
    AVR_INS_CBI,     // Clear Bit in I/O Register
    AVR_INS_LSL,     // Logical Shift Left
    AVR_INS_LSR,     // Logical Shift Right
    AVR_INS_ROL,     // Rotate Left Through Carry
    AVR_INS_ROR,     // Rotate Right Through Carry
    AVR_INS_ASR,     // Arithmetic Shift Right
    AVR_INS_SWAP,    // Swap Nibbles
    AVR_INS_BSET,    // Flag Set
    AVR_INS_BCLR,    // Flag Clear
    AVR_INS_BST,     // Bit Store from Register to T
    AVR_INS_BLD,     // Bit load from T to Register
    AVR_INS_SEC,     // Set Carry
    AVR_INS_CLC,     // Clear Carry
    AVR_INS_SEN,     // Set Negative Flag
    AVR_INS_CLN,     // Clear Negative Flag
    AVR_INS_SEZ,     // Set Zero Flag
    AVR_INS_CLZ,     // Clear Zero Flag
    AVR_INS_SEI,     // Global Interrupt Enable
    AVR_INS_CLI,     // Global Interrupt Disable
    AVR_INS_SES,     // Set Signed Test Flag
    AVR_INS_CLS,     // Clear Signed Test Flag
    AVR_INS_SEV,     // Set Overflow Flag
    AVR_INS_CLV,     // Clear Overflow Flag
    AVR_INS_SET,     // Set T in SREG
    AVR_INS_CLT,     // Clear T in SREG
    AVR_INS_SEH,     // Set Half Carry Flag in SREG
    AVR_INS_CLH,     // Clear Half Carry Flag in SREG
    
    // MCU Control Instructions
    AVR_INS_NOP,     // No Operation
    AVR_INS_SLEEP,   // Sleep
    AVR_INS_WDR,     // Watchdog Reset
    AVR_INS_BREAK,   // Break
    
    AVR_INS_ENDING
} avr_insn;

// AVR operand types
typedef enum avr_op_type {
    AVR_OP_INVALID = 0, // Uninitialized/invalid operand
    AVR_OP_REG,         // Register operand
    AVR_OP_IMM,         // Immediate operand
    AVR_OP_MEM,         // Memory operand
} avr_op_type;

// AVR memory operand
typedef struct avr_op_mem {
    avr_reg base;       // Base register
    int16_t disp;       // Displacement/offset
} avr_op_mem;

// Instruction operand
typedef struct cs_avr_op {
    avr_op_type type;   // Operand type
    union {
        avr_reg reg;    // Register value for REG operand
        int32_t imm;    // Immediate value for IMM operand
        avr_op_mem mem; // Memory operand
    };
} cs_avr_op;

// Instruction structure in AVR-specific format
typedef struct cs_avr {
    uint8_t op_count;   // Number of operands
    cs_avr_op operands[3]; // Up to 3 operands per instruction
} cs_avr;

#ifdef __cplusplus
}
#endif

#endif