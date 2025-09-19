#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#undef NULL
#define NULL ((void*)0)

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;
typedef size_t usize;
typedef uintptr_t uptr;

#define FATAL(msg)                                                               \
	do {                                                                     \
		fprintf(stderr, "FATAL %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
		exit(EXIT_FAILURE);                                              \
	} while (0)

#define KB(x) ((usize)(x) << 10)
#define MB(x) ((usize)(x) << 20)
#define GB(x) ((usize)(x) << 30)

#define MAX_INSTRUCTIONS (256 << 10)

typedef enum error_code {
	ERR_OK = 0,
	ERR_INVALID_ALIGNMENT = -1,
	ERR_OOM = -2,
	ERR_INVALID_ARGUMENT = -3,
	ERR_OVER_BOUND = -4,
	ERR_ARRAY_LIMIT = -5,
	ERR_FMT_LIMIT = -6,
	ERR_INVALID_INSTRUCTION = -7,
} ErrorCode;

#define PERM_BUFFER_SIZE MB(512)
#define DEBUG_UNINITIALIZED_BYTE 0xCD
static char g_perm[PERM_BUFFER_SIZE];

typedef struct arena {
	char* beg;
	char* end;
} Arena;

static void arena_init(Arena* a, char* buffer, usize size) {
	a->beg = buffer;
	a->end = buffer + size;
}

static void init_debug_buffer(char* buffer, usize size) {
	usize i;
	for (i = 0; i < size; i++) {
		buffer[i] = DEBUG_UNINITIALIZED_BYTE;
	}
}

#ifdef DEBUG_MEMORY
#define MAYBE_INIT_DEBUG_BUFFER(buf, size) init_debug_buffer(buf, size)
#else
#define MAYBE_INIT_DEBUG_BUFFER(buf, size) ((void)0)
#endif

static ErrorCode arena_alloc(Arena* a, void** ptr, usize nbytes, usize alignment) {
	uptr p;
	uptr aligned;
	char* result;

	if (nbytes == 0) {
		*ptr = NULL;
		return ERR_INVALID_ARGUMENT;
	}
	if (alignment == 0)
		alignment = 16;
	if ((alignment & (alignment - 1)) != 0) {
		*ptr = NULL;
		return ERR_INVALID_ALIGNMENT;
	}

	p = (uptr)a->beg;
	aligned = (p + alignment - 1) & ~(alignment - 1);
	result = (char*)aligned;

	if ((usize)(a->end - result) < nbytes) {
		*ptr = NULL;
		return ERR_OOM;
	}

	*ptr = result;
	a->beg = result + nbytes;
	return ERR_OK;
}

static ErrorCode arena_restore(Arena *a, char *savepoint) {
	ErrorCode r;
	r = ERR_OK;
	a->beg = savepoint;
	return r;
}

static ErrorCode arena_save(Arena *a, char **savepoint) {
	ErrorCode r;
	r = ERR_OK;
	*savepoint = a->beg;
	return r;
}

typedef struct str {
	char* data;
	usize len;
} Str;

static void str_init(Str* s, char* data, usize len) {
	s->data = data;
	s->len = len;
}

typedef enum width {
	WIDTH8 = 8,
	WIDTH16 = 16
} Width;

typedef enum mnemonic {
	MNEMONIC_UNIMPLEMENTED = 0,
	MNEMONIC_INVALID = 1,

	MNEMONIC_MOV,
	MNEMONIC_MOVS,
	MNEMONIC_ADD
} Mnemonic;

typedef enum reg {
	REG_NONE = 0,
	/* 8-bit */
	REG_AL,
	REG_CL,
	REG_DL,
	REG_BL,
	REG_AH,
	REG_CH,
	REG_DH,
	REG_BH,
	/* 16-bit */
	REG_AX,
	REG_CX,
	REG_DX,
	REG_BX,
	REG_SP,
	REG_BP,
	REG_SI,
	REG_DI
} Reg;

static const Reg registers[16] = {
	/* 8-bit */
	REG_AL,
	REG_CL,
	REG_DL,
	REG_BL,
	REG_AH,
	REG_CH,
	REG_DH,
	REG_BH,
	/* 16-bit */
	REG_AX,
	REG_CX,
	REG_DX,
	REG_BX,
	REG_SP,
	REG_BP,
	REG_SI,
	REG_DI,
};

static char* registers_to_cstr[16] = {
	/* 8-bit */
	"al",
	"cl",
	"dl",
	"bl",
	"ah",
	"ch",
	"dh",
	"bh",
	/* 16-bit */
	"ax",
	"cx",
	"dx",
	"bx",
	"sp",
	"bp",
	"si",
	"di",
};

static const Reg ea_base_register[8] = {
	REG_BX,
	REG_BX,
	REG_BP,
	REG_BP,
	REG_SI,
	REG_DI,
	REG_BP,
	REG_BX,
};

static const Reg ea_index_register[8] = {
	REG_SI,
	REG_DI,
	REG_SI,
	REG_DI,
	REG_NONE,
	REG_NONE,
	REG_NONE,
	REG_NONE,
};

typedef enum segment_reg {
	SEG_NONE = 0,
	SEG_ES,
	SEG_CS,
	SEG_SS,
	SEG_DS
} SegmentReg;

typedef enum operand_kind {
	OPERAND_NONE = 0,
	OPERAND_REG,	 /* general-purpose register (8/16) */
	OPERAND_SEGREG,	 /* segment register */
	OPERAND_MEM,	 /* memory reference with 8086 EA (base/index/disp + optional seg
			    override) */
	OPERAND_IMM,	 /* immediate (8/16) */
	OPERAND_RELDISP, /* relative displacement (for Jcc/LOOP/JCXZ), signed 8 or 16
			  */
	OPERAND_PTR16	 /* far pointer immediate: seg:off (for JMP FAR/CALL FAR) */
} OperandKind;

typedef struct memea {
	SegmentReg seg_override;
	Reg base;
	Reg index;
	int has_disp;
	i16 disp;
} MemEA;

static void memea_init(MemEA* m) {
	m->seg_override = SEG_NONE;
	m->base = REG_NONE;
	m->index = REG_NONE;
	m->has_disp = 0;
	m->disp = 0;
}

typedef struct operand {
	OperandKind kind;
	Width width;
	union {
		struct
		{
			Reg reg;
		} reg;
		struct
		{
			SegmentReg segreg;
		} segreg;
		struct
		{
			MemEA memea;
		} memea;
		struct
		{
			u16 imm;
		} imm;
		struct
		{
			i16 reldisp;
		} reldisp;
		struct
		{
			u16 seg, off;
		} ptr16;
	};
} Operand;

static void operand_init(Operand* op) {
	op->kind = OPERAND_NONE;
	op->width = WIDTH8;
	op->reg.reg = REG_NONE;
}

typedef struct instruction {
	Mnemonic mnemonic;
	Operand operands[2];
	u8 operand_count;
	/* u8 prefixes; bitmask: LOCK/REP/... */
	int has_modrm;
	u8 modrm;
	Width width;
	Str raw;
} Instruction;

static void instruction_init(Instruction* instr) {
	instr->mnemonic = MNEMONIC_UNIMPLEMENTED;
	operand_init(&instr->operands[0]);
	operand_init(&instr->operands[1]);
	instr->operand_count = 0;
	instr->has_modrm = 0;
	instr->modrm = 0;
	instr->width = WIDTH8;
	instr->raw.data = NULL;
	instr->raw.len = 0;
}

static u8 modrm_mod(u8 modrm) {
	return modrm >> 6;
}
static u8 modrm_reg(u8 modrm) {
	return (modrm >> 3) & 7;
}
static u8 modrm_rm(u8 modrm) {
	return modrm & 7;
}

static Instruction g_instructions_storage[MAX_INSTRUCTIONS];
typedef struct instruction_array {
	Instruction* data;
	usize len;
	usize cap;
} InstructionArray;

static void instruction_array_init(InstructionArray* arr, Instruction* storage,
				   usize capacity) {
	arr->data = storage;
	arr->len = 0;
	arr->cap = capacity;
}

static ErrorCode instruction_array_add(InstructionArray* instr_array,
				       Instruction* instr) {
	if (!instr_array || !instr)
		return ERR_INVALID_ARGUMENT;
	if (instr_array->len >= instr_array->cap)
		return ERR_ARRAY_LIMIT;
	if (!instr_array->data)
		return ERR_INVALID_ARGUMENT;

	memcpy(&instr_array->data[instr_array->len], instr, sizeof(Instruction));
	instr_array->len++;
	return ERR_OK;
}

/* ========== DECODING ========== */

static ErrorCode fetch8(Str bytes, usize* at, u8* out) {
	if (!out || !at)
		return ERR_INVALID_ARGUMENT;
	if (*at >= bytes.len)
		return ERR_OVER_BOUND;
	if (bytes.len - *at < 1)
		return ERR_OVER_BOUND;

	*out = (u8)bytes.data[*at];
	*at += 1;
	return ERR_OK;
}

static ErrorCode fetch16(Str bytes, usize* at, u16* out) {
	u16 lo;
	u16 hi;

	if (!out || !at)
		return ERR_INVALID_ARGUMENT;
	if (*at >= bytes.len)
		return ERR_OVER_BOUND;
	if (bytes.len - *at < 2)
		return ERR_OVER_BOUND;

	lo = (u8)bytes.data[*at];
	hi = (u8)bytes.data[*at + 1];
	*out = (u16)((hi << 8) | lo);
	*at += 2;
	return ERR_OK;
}

static ErrorCode decode_mov(u8 opcode, Str bytes, usize* at, Instruction* out) {
	ErrorCode r;
	u8 direction;
	u8 val;

	r = ERR_OK;
	out->mnemonic = MNEMONIC_MOV;
	
	switch (opcode) {
	/* MOV reg, reg/mem */
	case 0x88:
	case 0x89:
	case 0x8A:
	case 0x8B:
	{
		u8 mod, reg, rm;
		Operand op0, op1;

		r = fetch8(bytes, at, &val);
		if (r != ERR_OK) goto _end;

		/*
		D field, generally specifies the ‘‘direction’’ of the operation:
		1 = the REG field in the second byte identifies the
		destination operand;
		0 = the REG field identifies the source operand.
		*/
		direction = ((opcode >> 1) & 0x01);
		out->width = (opcode & 0x01) ? WIDTH16 : WIDTH8;

		operand_init(&op0);
		operand_init(&op1);

		out->has_modrm = 1;
		out->modrm = val;

		mod = modrm_mod(val);
		reg = modrm_reg(val);
		rm = modrm_rm(val);

		op0.kind = OPERAND_REG;
		op0.width = out->width;
		op0.reg.reg = (out->width == WIDTH8) ? registers[reg] : registers[reg + 8];
		op1.width = out->width;
		out->operand_count = 2;

		switch (mod) {
		case 3: /* Register mode */
			op1.kind = OPERAND_REG;
			op1.reg.reg = (out->width == WIDTH8) ? registers[rm] : registers[rm + 8];
			break;
		case 0:
		case 1:
		case 2: /* memory mode */
			op1.kind = OPERAND_MEM;
			memea_init(&op1.memea.memea);
			op1.memea.memea.base = ea_base_register[rm];
			op1.memea.memea.index = ea_index_register[rm];
			switch (mod) {
			case 0:
				if (rm == 6) { /* exception: direct addressing */
					u16 disp16;
					op1.memea.memea.base = REG_NONE;
					op1.memea.memea.index = REG_NONE;
					op1.memea.memea.has_disp = 1;
					r = fetch16(bytes, at, &disp16);
					if (r != ERR_OK)
						goto _end;
					op1.memea.memea.disp = (i16)disp16;
				}
				break;
			case 1: {
				u8 disp8;
				op1.memea.memea.has_disp = 1;
				r = fetch8(bytes, at, &disp8);
				op1.memea.memea.disp = (i8)disp8;
				if (r != ERR_OK)
					goto _end;
			} break;
			case 2: {
				u16 disp16;
				op1.memea.memea.has_disp = 1;
				r = fetch16(bytes, at, &disp16);
				op1.memea.memea.disp = (i16)disp16;
				if (r != ERR_OK)
					goto _end;
			} break;
			}
			break;
		}

		if (direction == 1) {
			out->operands[0] = op0;
			out->operands[1] = op1;
		} else {
			out->operands[0] = op1;
			out->operands[1] = op0;
		}
	} break;

	/* MOV segreg, reg/mem */
	/* case 0x8C: */
	/* case 0x8E: {} break; */

	/* MOV reg, imm */
	case 0xB0:
	case 0xB1:
	case 0xB2:
	case 0xB3:
	case 0xB4:
	case 0xB5:
	case 0xB6:
	case 0xB7:
	case 0xB8:
	case 0xB9:
	case 0xBA:
	case 0xBB:
	case 0xBC:
	case 0xBD:
	case 0xBE:
	case 0xBF: {
		u8 reg;
		u16 imm16_val;
		u8 imm8_val;
		Operand op0, op1;

		operand_init(&op0);
		operand_init(&op1);

		out->width = ((opcode >> 3) & 0x01) ? WIDTH16 : WIDTH8;
		out->has_modrm = 0;

		reg = opcode & 7;

		op0.kind = OPERAND_REG;
		op0.reg.reg = (out->width == WIDTH8) ? registers[reg] : registers[reg + 8];
		op0.width = out->width;

		op1.kind = OPERAND_IMM;
		op1.width = out->width;

		if (op1.width == WIDTH8) {
			r = fetch8(bytes, at, &imm8_val);
		} else {
			r = fetch16(bytes, at, &imm16_val);
		}
		if (r != ERR_OK) goto _end;
		op1.imm.imm = (op1.width == WIDTH8) ? imm8_val : imm16_val;

		out->operand_count = 2;
		out->operands[0] = op0;
		out->operands[1] = op1;
	} break;

	/* MOV memea, imm */
	case 0xC6:
	case 0xC7: {
		u8 mod, rm;
		u16 imm16_val;
		u8 imm8_val;
		Operand op0, op1;

		operand_init(&op0);
		operand_init(&op1);

		out->width = (opcode & 0x01) ? WIDTH16 : WIDTH8;
		op0.width = out->width;
		op1.width = out->width;

		r = fetch8(bytes, at, &val);
		if (r != ERR_OK) goto _end;

		out->has_modrm = 1;
		out->modrm = val;

		mod = modrm_mod(val);
		rm = modrm_rm(val);

		switch (mod) {
		case 3: /* Register mode */
			op0.kind = OPERAND_NONE;
			r = ERR_INVALID_INSTRUCTION;
			goto _end;
			break;
		case 0:
		case 1:
		case 2: /* memory mode */
			op0.kind = OPERAND_MEM;
			memea_init(&op0.memea.memea);
			op0.memea.memea.base = ea_base_register[rm];
			op0.memea.memea.index = ea_index_register[rm];
			switch (mod) {
			case 0:
				if (rm == 6) { /* exception: direct addressing */
					u16 disp16;
					op0.memea.memea.base = REG_NONE;
					op0.memea.memea.index = REG_NONE;
					op0.memea.memea.has_disp = 1;
					r = fetch16(bytes, at, &disp16);
					if (r != ERR_OK)
						goto _end;
					op0.memea.memea.disp = (i16)disp16;
				}
				break;
			case 1: {
				u8 disp8;
				op0.memea.memea.has_disp = 1;
				r = fetch8(bytes, at, &disp8);
				op0.memea.memea.disp = (i8)disp8;
				if (r != ERR_OK)
					goto _end;
			} break;
			case 2: {
				u16 disp16;
				op0.memea.memea.has_disp = 1;
				r = fetch16(bytes, at, &disp16);
				op0.memea.memea.disp = (i16)disp16;
				if (r != ERR_OK)
					goto _end;
			} break;
			}
			break;
		}

		if (op1.width == WIDTH8) {
			r = fetch8(bytes, at, &imm8_val);
		} else {
			r = fetch16(bytes, at, &imm16_val);
		}
		if (r != ERR_OK) goto _end;
		op1.imm.imm = (op1.width == WIDTH8) ? imm8_val : imm16_val;
		op1.kind = OPERAND_IMM;

		out->operand_count = 2;
		out->operands[0] = op0;
		out->operands[1] = op1;
	} break;

	default:
		FATAL("THIS MOV IS NOT IMPLEMENTED YET");
		break;
	}
_end:
	return r;
}

static ErrorCode emu8086_decode(Arena* perm, Str bytes,
				InstructionArray* instructions) {
	ErrorCode r;
	usize at;
	usize prev_at;
	u8 val;
	Instruction instr;

	if (!perm || !instructions)
		return ERR_INVALID_ARGUMENT;
	if (!bytes.data && bytes.len > 0)
		return ERR_INVALID_ARGUMENT;

	r = ERR_OK;
	at = 0;
	prev_at = 0;
	val = 0;

	instruction_init(&instr);
	while (at < bytes.len) {
		instruction_init(&instr);
		instr.raw.data = &bytes.data[at];
		r = fetch8(bytes, &at, &val);
		if (r != ERR_OK)
			goto _end;
		switch (val) {
		/* MOV */
		case 0x88:
		case 0x89:
		case 0x8A:
		case 0x8B:
		case 0x8C:
		case 0x8E:
		case 0xA0:
		case 0xA1:
		case 0xA2:
		case 0xA3:
		case 0xB0:
		case 0xB1:
		case 0xB2:
		case 0xB3:
		case 0xB4:
		case 0xB5:
		case 0xB6:
		case 0xB7:
		case 0xB8:
		case 0xB9:
		case 0xBA:
		case 0xBB:
		case 0xBC:
		case 0xBD:
		case 0xBE:
		case 0xBF:
		case 0xC6:
		case 0xC7:
		{
			r = decode_mov(val, bytes, &at, &instr);
			if (r != ERR_OK) goto _end;
		} break;

		/* MOVS:               A4, A5 */
		default: {
			instr.mnemonic = MNEMONIC_UNIMPLEMENTED;
		}
		}
		instr.raw.len = at - prev_at;
		r = instruction_array_add(instructions, &instr);
		if (r != ERR_OK)
			goto _end;
		prev_at = at;
	}
_end:
	return r;
}

static char *cstr_from_mnemonic(Mnemonic m) {
	switch(m) {
	case MNEMONIC_MOV:
		return "mov";
	case MNEMONIC_UNIMPLEMENTED:
		return "UNIMPLEMENTED_MNEMONIC";
	case MNEMONIC_INVALID:
		return "INVALID_MNEMONIC";
	default:
		return "UNIMPLEMENTED!!!";
	}
}

static u32 fmt_append_u32_as_dec(char *str, u32 *str_len, u32 str_cap, u32 value) {
	ErrorCode r;

	char buf[10];
	u32 i, j, len;
	char *dst; 

	r = ERR_OK;
	
	dst = str + *str_len;

	i = 0;
	if (value == 0) { 
		dst[0] = '0'; 
		*str_len += 1;
		return r;
	}
	while (value) { 
		buf[i++] = '0' + (value % 10); 
		value /= 10; 
	}
	len = i;
	for (j = 0; j < len; ++j) {
		dst[j] = buf[len-1-j];
	}
	*str_len += len;
	return r;
}

static ErrorCode
fmt_append_str(char *str, u32 *str_len, u32 str_cap, char *s, u32 len) {
	ErrorCode r;
	r = ERR_OK;
	if (str_cap - *str_len < len) {
		return ERR_FMT_LIMIT;
	}
	memcpy(&str[(*str_len)], s, len);
	*str_len += len;
	return r;
}


static ErrorCode
fmt_append_operand(char *str, u32 *str_len, u32 str_cap, Operand op) {
	ErrorCode r;
	char *cstr;
	u32 displacement;

	r = ERR_OK;

	switch(op.kind) {
		case OPERAND_REG: {
			cstr = registers_to_cstr[op.reg.reg-1];
			r = fmt_append_str(str, str_len, str_cap, cstr, (u32)strlen(cstr));
			if (r != ERR_OK) return r;
		} break;
		case OPERAND_IMM: {
			r = fmt_append_u32_as_dec(str, str_len, str_cap, op.imm.imm);
			if (r != ERR_OK) return r;
		} break;
		case OPERAND_MEM: {
			r = fmt_append_str(str, str_len, str_cap, "[", 1);
			if (r != ERR_OK) return r;
			if (op.memea.memea.base != REG_NONE) {
				cstr = registers_to_cstr[op.memea.memea.base-1];
				r = fmt_append_str(str, str_len, str_cap, cstr, (u32)strlen(cstr));
				if (r != ERR_OK) return r;
				if (op.memea.memea.index != REG_NONE) {
					r = fmt_append_str(str, str_len, str_cap, "+", 1);
					if (r != ERR_OK) return r;
					cstr = registers_to_cstr[op.memea.memea.index-1];
					r = fmt_append_str(str, str_len, str_cap, cstr, (u32)strlen(cstr));
					if (r != ERR_OK) return r;
				}
				if (op.memea.memea.has_disp) {
					cstr = op.memea.memea.disp > 0 ? "+" : "-";
					r = fmt_append_str(str, str_len, str_cap, cstr, 1);
					if (r != ERR_OK) return r;
					if (op.memea.memea.disp < 0) {
						displacement = (u32)(-(i32)op.memea.memea.disp);
					} else {
						displacement = (u32)op.memea.memea.disp;
					}
					r = fmt_append_u32_as_dec(str, str_len, str_cap, displacement);
					if (r != ERR_OK) return r;
				}
			} else {
				r = fmt_append_u32_as_dec(str, str_len, str_cap, (u32)op.memea.memea.disp);
				if (r != ERR_OK) return r;
			}
			r = fmt_append_str(str, str_len, str_cap, "]", 1);
			if (r != ERR_OK) return r;
		} break;
		case OPERAND_NONE: {
			r = fmt_append_str(str, str_len, str_cap, "OPERAND_NONE", sizeof("OPERAND_NONE")-1);
			if (r != ERR_OK) return r;
		} break;
		default:
			r = fmt_append_str(str, str_len, str_cap, "UNIMPLEMENTED", sizeof("UNIMPLEMENTED")-1);
			if (r != ERR_OK) return r;
	}
	return r;
}

static ErrorCode emu8086_print(Arena *arena, InstructionArray* instructions) {
	ErrorCode r = ERR_OK;
	usize i;
	Instruction instr;
	
	char *cstr;
	u32 str_cap, str_len;
	char *str;
	char *savepoint;

	str_len = 0;
	str_cap = 1024; 
	r = arena_alloc(arena, (void **)&str, str_cap, 0);
	if (r != ERR_OK) return r;
	savepoint = str;

	fprintf(stdout, "[bits 16]\n");
	for (i = 0; i < instructions->len; i++) {
		str = savepoint;
		str_len = 0;

		instr = instructions->data[i];

		cstr = cstr_from_mnemonic(instr.mnemonic);

		r = fmt_append_str(str, &str_len, str_cap, cstr, (u32)strlen(cstr));
		if (r != ERR_OK) return r;

		if (instr.operand_count > 0) {
			r = fmt_append_str(str, &str_len, str_cap, " ", 1);
			if (r != ERR_OK) return r;

			if (instr.operands[0].kind == OPERAND_MEM && instr.operands[1].kind == OPERAND_IMM) {
				cstr = instr.width == WIDTH8 ? "byte" : "word";
				r = fmt_append_str(str, &str_len, str_cap, cstr, (u32)strlen(cstr));
				if (r != ERR_OK) return r;
			}
			r = fmt_append_str(str, &str_len, str_cap, " ", 1);
			if (r != ERR_OK) return r;

			r = fmt_append_operand(str, &str_len, str_cap, instr.operands[0]);
			if (r != ERR_OK) return r;

			if (instr.operand_count > 1) {
				r = fmt_append_str(str, &str_len, str_cap, ", ", 2);
				if (r != ERR_OK) return r;
				r = fmt_append_operand(str, &str_len, str_cap, instr.operands[1]);
				if (r != ERR_OK) return r;
			}
		}
		r = fmt_append_str(str, &str_len, str_cap, "\n", 1);
		if (r != ERR_OK) return r;
		fprintf(stdout, "%.*s", str_len, str);

	}
	return r;
}

int main(int argc, char** argv) {
	Arena perm_arena;
	InstructionArray instructions;
	FILE* file;
	Str bytes;
	ErrorCode r;
	usize avail, got;

	MAYBE_INIT_DEBUG_BUFFER(g_perm, PERM_BUFFER_SIZE);

	arena_init(&perm_arena, g_perm, PERM_BUFFER_SIZE);
	instruction_array_init(&instructions, g_instructions_storage,
			       sizeof(g_instructions_storage) /
				       sizeof(g_instructions_storage[0]));

	file = NULL;
	if (argc > 1) {
		file = fopen(argv[1], "rb");
		if (!file) {
			FATAL("Error: cannot open file");
		}
	} else {
		file = stdin;
	}

	str_init(&bytes, (char*)perm_arena.beg, 0);

	avail = perm_arena.end - perm_arena.beg;
	got = fread(bytes.data, 1, avail, file);
	if (got == avail) {
		FATAL("Error: file too big");
	}
	if (got == 0) {
		if (ferror(file)) {
			FATAL("Error: file read error");
		} else {
			FATAL("Error: file is empty");
		}
	}
	perm_arena.beg += got;
	bytes.len = got;

	r = emu8086_decode(&perm_arena, bytes, &instructions);
	if (r != ERR_OK) {
		FATAL("Fail to decode instructions");
	}

	r = emu8086_print(&perm_arena, &instructions);
	if (r != ERR_OK) {
		FATAL("Fail to print instructions");
	}

	if (file != stdin) {
		fclose(file);
	}

	return 0;
}
