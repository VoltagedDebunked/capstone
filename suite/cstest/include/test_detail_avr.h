// Copyright © 2025 VoltagedDebunked <rusindanilo@gmail.com>
// SPDX-License-Identifier: BSD-3

#ifndef TEST_DETAIL_AVR_H
#define TEST_DETAIL_AVR_H

#include "test_compare.h"
#include <cyaml/cyaml.h>
#include <capstone/capstone.h>

typedef struct {
	char *type;
	char *reg;
	int32_t imm;
	char *mem_base;
	int16_t mem_disp;
} TestDetailAVROp;

static const cyaml_schema_field_t test_detail_avr_op_mapping_schema[] = {
	CYAML_FIELD_STRING_PTR("type", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailAVROp, type, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("reg", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailAVROp, reg, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT("imm", CYAML_FLAG_OPTIONAL, TestDetailAVROp, imm),
	CYAML_FIELD_STRING_PTR(
		"mem_base", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailAVROp, mem_base, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT("mem_disp", CYAML_FLAG_OPTIONAL, TestDetailAVROp,
			mem_disp),
	CYAML_FIELD_END
};

static const cyaml_schema_value_t test_detail_avr_op_schema = {
	CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER, TestDetailAVROp,
			    test_detail_avr_op_mapping_schema),
};

typedef struct {
	TestDetailAVROp **operands;
	uint32_t operands_count;
} TestDetailAVR;

static const cyaml_schema_field_t test_detail_avr_mapping_schema[] = {
	CYAML_FIELD_SEQUENCE(
		"operands", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailAVR, operands, &test_detail_avr_op_schema, 0,
		CYAML_UNLIMITED), // 0-MAX options
	CYAML_FIELD_END
};

TestDetailAVR *test_detail_avr_new();
TestDetailAVR *test_detail_avr_clone(TestDetailAVR *detail);
void test_detail_avr_free(TestDetailAVR *detail);

TestDetailAVROp *test_detail_avr_op_new();
TestDetailAVROp *test_detail_avr_op_clone(TestDetailAVROp *detail);
void test_detail_avr_op_free(TestDetailAVROp *detail);

bool test_expected_avr(csh *handle, cs_avr *actual,
		       TestDetailAVR *expected);

#endif // TEST_DETAIL_AVR_H