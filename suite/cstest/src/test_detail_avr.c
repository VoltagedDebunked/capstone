// Copyright © 2025 VoltagedDebunked <rusindanilo@gmail.com>
// SPDX-License-Identifier: BSD-3

#include "test_compare.h"
#include "test_detail_avr.h"
#include <capstone/capstone.h>
#include <stdio.h>
#include <string.h>

TestDetailAVR *test_detail_avr_new()
{
	return cs_mem_calloc(sizeof(TestDetailAVR), 1);
}

void test_detail_avr_free(TestDetailAVR *detail)
{
	if (!detail) {
		return;
	}
	for (size_t i = 0; i < detail->operands_count; ++i) {
		test_detail_avr_op_free(detail->operands[i]);
	}
	cs_mem_free(detail->operands);
	cs_mem_free(detail);
}

TestDetailAVR *test_detail_avr_clone(TestDetailAVR *detail)
{
	TestDetailAVR *clone = test_detail_avr_new();

	clone->operands_count = detail->operands_count;
	if (detail->operands_count > 0) {
		clone->operands = cs_mem_calloc(sizeof(TestDetailAVROp *),
						detail->operands_count);
	}
	for (size_t i = 0; i < detail->operands_count; ++i) {
		clone->operands[i] =
			test_detail_avr_op_clone(detail->operands[i]);
	}

	return clone;
}

TestDetailAVROp *test_detail_avr_op_new()
{
	return cs_mem_calloc(sizeof(TestDetailAVROp), 1);
}

TestDetailAVROp *test_detail_avr_op_clone(TestDetailAVROp *op)
{
	TestDetailAVROp *clone = test_detail_avr_op_new();

	clone->type = op->type ? strdup(op->type) : NULL;
	clone->reg = op->reg ? strdup(op->reg) : NULL;
	clone->mem_base = op->mem_base ? strdup(op->mem_base) : NULL;
	clone->imm = op->imm;
	clone->mem_disp = op->mem_disp;

	return clone;
}

void test_detail_avr_op_free(TestDetailAVROp *op)
{
	if (!op) {
		return;
	}
	cs_mem_free(op->type);
	cs_mem_free(op->reg);
	cs_mem_free(op->mem_base);
	cs_mem_free(op);
}

bool test_expected_avr(csh *handle, cs_avr *actual,
		       TestDetailAVR *expected)
{
	assert(handle && actual && expected);

	if (expected->operands_count == 0) {
		return true;
	}
	compare_uint8_ret(actual->op_count, expected->operands_count, false);
	for (size_t i = 0; i < actual->op_count; ++i) {
		cs_avr_op *op = &actual->operands[i];
		TestDetailAVROp *eop = expected->operands[i];
		compare_enum_ret(op->type, eop->type, false);
		switch (op->type) {
		default:
			fprintf(stderr,
				"AVR op type %" PRId32 " not handled.\n",
				op->type);
			return false;
		case AVR_OP_REG:
			compare_reg_ret(*handle, op->reg, eop->reg, false);
			break;
		case AVR_OP_IMM:
			compare_int32_ret(op->imm, eop->imm, false);
			break;
		case AVR_OP_MEM:
			compare_reg_ret(*handle, op->mem.base, eop->mem_base,
					false);
			compare_int16_ret(op->mem.disp, eop->mem_disp, false);
			break;
		}
	}

	return true;
}