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
	ERR_str_LIMIT = -6,
	ERR_INVALID_INSTRUCTION = -7,
	ERR_MNEMONIC_UNIMPLEMENTED = -8,
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

static char* segment_registers_to_cstr[4] = {
	"es",
	"cs",
	"ss",
	"ds"
};

static enum segment_reg segment_registers[4] = {
	SEG_ES,
	SEG_CS,
	SEG_SS,
	SEG_DS
};

typedef enum operand_kind {
	OPERAND_NONE = 0,
	OPERAND_REG,
	OPERAND_SEGREG,
	OPERAND_MEM,
	OPERAND_IMM,
	OPERAND_RELDISP, /* relative displacement (for Jcc/LOOP/JCXZ), signed 8 or 16 */
	OPERAND_PTR16	 /* far pointer immediate: seg:off (for JMP FAR/CALL FAR) */
} OperandKind;

typedef struct memea {
	SegmentReg seg_override;
	Reg base;
	Reg index;
	int has_disp;
	i16 disp;
	int has_address;
	u16 address;
} MemEA;

static void memea_init(MemEA* m) {
	m->seg_override = SEG_NONE;
	m->base = REG_NONE;
	m->index = REG_NONE;
	m->has_disp = 0;
	m->disp = 0;
	m->has_address = 0;
	m->address = 0;
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

static void operand_init_memea(Operand* op) {
	op->kind = OPERAND_MEM;
	op->memea.memea.seg_override = SEG_NONE;
	op->memea.memea.base = REG_NONE;
	op->memea.memea.index = REG_NONE;
	op->memea.memea.has_disp = 0;
	op->memea.memea.disp = 0;
	op->memea.memea.has_address = 0;
	op->memea.memea.address = 0;
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

static ErrorCode emu8086_decode(Arena* perm, Str bytes,
				InstructionArray* instructions) {
	ErrorCode r;
	usize at;
	usize prev_at;
	u8 head_byte, byte;
	Instruction instr;
	Operand tmp_operand;
	
	u8 direction;
	Width width;
	/*
		D field, generally specifies the ‘‘direction’’ of the operation:
		1 = the REG field in the second byte identifies the destination operand;
		0 = the REG field identifies the source operand.
	*/
	u8 mod, reg, rm;
	u8 disp8;
	u16 disp16;
	u16 imm16;
	u8 imm8;
	u16 address16;

	if (!perm || !instructions)
		return ERR_INVALID_ARGUMENT;
	if (!bytes.data && bytes.len > 0)
		return ERR_INVALID_ARGUMENT;

	r = ERR_OK;
	at = 0;
	prev_at = 0;
	byte = 0;

	instruction_init(&instr);
	while (at < bytes.len) {
		operand_init(&tmp_operand);
		instruction_init(&instr);
		instr.raw.data = &bytes.data[at];
		r = fetch8(bytes, &at, &head_byte);
		if (r != ERR_OK) goto _end;
		switch (head_byte) {
		/*
			case 0x00:
			case 0x01:
			case 0x02:
			case 0x03:
			case 0x04:
			case 0x05: {
			} break;
		*/
			/* MOV */
			case 0x88:
			case 0x89:
			case 0x8A:
			case 0x8B:
			case 0x8C:
			case 0x8E:
			{
				instr.mnemonic = MNEMONIC_MOV;
				direction = ((head_byte >> 1) & 0x01);
				if (head_byte == 0x8C || head_byte == 0x8E) {
					width = WIDTH16;
				} else {
					width = (head_byte & 0x01) ? WIDTH16 : WIDTH8;
				}
				r = fetch8(bytes, &at, &byte);
				if (r != ERR_OK) goto _end;
				instr.has_modrm = 1;
				instr.modrm = byte;
				instr.width = width;
				mod = modrm_mod(byte);
				reg = modrm_reg(byte);
				rm = modrm_rm(byte);
				if (head_byte == 0x8C || head_byte == 0x8E) {
					instr.operands[0].kind = OPERAND_SEGREG;
					instr.operands[0].segreg.segreg = segment_registers[reg];
				} else {
					instr.operands[0].kind = OPERAND_REG;
					instr.operands[0].width = instr.width;
					instr.operands[0].reg.reg = (instr.width == WIDTH8) ? registers[reg] : registers[reg + 8];
				}

				instr.operands[1].width = instr.width;
				if (mod == 3) {
					instr.operands[1].kind = OPERAND_REG;
					instr.operands[1].reg.reg = (instr.width == WIDTH8) ? registers[rm] : registers[rm + 8];
				} else if (mod == 0 || mod == 1 || mod == 2) {
					operand_init_memea(&instr.operands[1]);
					instr.operands[1].memea.memea.base = ea_base_register[rm];
					instr.operands[1].memea.memea.index = ea_index_register[rm];
					if (mod == 0 && rm == 6) {
						instr.operands[1].memea.memea.base = REG_NONE;
						instr.operands[1].memea.memea.index = REG_NONE;
						r = fetch16(bytes, &at, &address16);
						if (r != ERR_OK) goto _end;
						instr.operands[1].memea.memea.address = address16;
						instr.operands[1].memea.memea.has_address = 1;
					} else if (mod == 1) {
						instr.operands[1].memea.memea.has_disp = 1;
						r = fetch8(bytes, &at, &disp8);
						instr.operands[1].memea.memea.disp = (i8)disp8;
						if (r != ERR_OK) goto _end;
					} else if (mod == 2) {
						instr.operands[1].memea.memea.has_disp = 1;
						r = fetch16(bytes, &at, &disp16);
						instr.operands[1].memea.memea.disp = (i16)disp16;
						if (r != ERR_OK) goto _end;
					}
				}
				if (direction == 1) {
				} else {
					tmp_operand = instr.operands[0];
					instr.operands[0] = instr.operands[1];
					instr.operands[1] = tmp_operand;
				}
				instr.operand_count = 2;
			} break;
			/* mov accumulator, mem */
			case 0xA0:
			case 0xA1:
			case 0xA2:
			case 0xA3:
			{
				instr.mnemonic = MNEMONIC_MOV;
				direction = ((head_byte >> 1) & 0x01);
				instr.width = (head_byte & 0x01) ? WIDTH16 : WIDTH8;
				instr.operands[1].kind = OPERAND_REG;
				operand_init_memea(&instr.operands[0]);
				if (instr.width == WIDTH8) {
					instr.operands[1].reg.reg = REG_AL;
				} else {
					instr.operands[1].reg.reg = REG_AX;
				}
				r = fetch16(bytes, &at, &address16);
				if (r != ERR_OK) goto _end;
				instr.operands[0].memea.memea.address = address16;
				instr.operands[0].memea.memea.has_address = 1;
				if (direction == 1) {
				} else {
					tmp_operand = instr.operands[0];
					instr.operands[0] = instr.operands[1];
					instr.operands[1] = tmp_operand;
				}
				instr.operand_count = 2;
			} break;
			/* MOVS: A4, A5 */
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
			{
				instr.mnemonic = MNEMONIC_MOV;
				instr.width = ((head_byte >> 3) & 0x01) ? WIDTH16 : WIDTH8;
				instr.has_modrm = 0;
				reg = head_byte & 7;
				instr.operands[0].kind = OPERAND_REG;
				instr.operands[0].width = instr.width;
				instr.operands[1].kind = OPERAND_IMM;
				instr.operands[1].width = instr.width;
				if (instr.width == WIDTH8) {
					instr.operands[0].reg.reg = registers[reg];
					r = fetch8(bytes, &at, &imm8);
					if (r != ERR_OK) goto _end;
					instr.operands[1].imm.imm = imm8;
				} else {
					instr.operands[0].reg.reg = registers[reg + 8];
					r = fetch16(bytes, &at, &imm16);
					if (r != ERR_OK) goto _end;
					instr.operands[1].imm.imm = imm16;
				}
				instr.operand_count = 2;
			} break;
			/* MOV memea, imm */
			case 0xC6:
			case 0xC7:
			{
				instr.mnemonic = MNEMONIC_MOV;
				instr.width = (head_byte & 0x01) ? WIDTH16 : WIDTH8;
				instr.has_modrm = 1;
				instr.operands[0].width = instr.width;
				instr.operands[1].width = instr.width;
				r = fetch8(bytes, &at, &byte);
				if (r != ERR_OK) goto _end;
				instr.modrm = byte;
				mod = modrm_mod(byte);
				rm = modrm_rm(byte);
				if (mod == 3) {
					r = ERR_INVALID_INSTRUCTION;
					goto _end;
				} else if (mod == 0 || mod == 1 || mod == 2) {
					operand_init_memea(&instr.operands[0]);
					instr.operands[0].memea.memea.base = ea_base_register[rm];
					instr.operands[0].memea.memea.index = ea_index_register[rm];
					if (mod == 0) {
						if (rm == 6) {
							instr.operands[0].memea.memea.base = REG_NONE;
							instr.operands[0].memea.memea.index = REG_NONE;
							r = fetch16(bytes, &at, &address16);
							if (r != ERR_OK) goto _end;
							instr.operands[0].memea.memea.address = address16;
							instr.operands[0].memea.memea.has_address = 1;
						}
					} else if (mod == 1) {
						instr.operands[0].memea.memea.has_disp = 1;
						r = fetch8(bytes, &at, &disp8);
						if (r != ERR_OK) goto _end;
						instr.operands[0].memea.memea.disp = (i8)disp8;
					} else if (mod == 2) {
						instr.operands[0].memea.memea.has_disp = 1;
						r = fetch16(bytes, &at, &disp16);
						if (r != ERR_OK) goto _end;
						instr.operands[0].memea.memea.disp = (i16)disp16;
					}
				}

				instr.operands[1].kind = OPERAND_IMM;
				if (instr.width == WIDTH8) {
					r = fetch8(bytes, &at, &imm8);
					if (r != ERR_OK) goto _end;
					instr.operands[1].imm.imm = imm8;
				} else {
					r = fetch16(bytes, &at, &imm16);
					if (r != ERR_OK) goto _end;
					instr.operands[1].imm.imm = imm16;
				}

				instr.operand_count = 2;
			} break;

			default: {
				instr.mnemonic = MNEMONIC_UNIMPLEMENTED;
				r = ERR_MNEMONIC_UNIMPLEMENTED;
			}
		}
		instr.raw.len = at - prev_at;
		r = instruction_array_add(instructions, &instr);
		if (r != ERR_OK) goto _end;
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

static ErrorCode str_append_u32_as_dec(char *str, u32 *str_len, u32 str_cap, u32 value) {
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
str_append_u32_as_hex(char *str, u32 *str_len, u32 str_cap, u32 value) {
	static const char *hex_ascii = "0123456789abcdef";
	ErrorCode r;
	r = ERR_OK;

	char buf[10];
	u32 i, j, len;
	char *dst;

	dst = str + *str_len;

	i = 0;
	if (value == 0) { 
		buf[i++] = '0';
	}

	while(value) {
		buf[i++] = hex_ascii[value % 16];
		value /= 16;
	}
	len = i;
	for (j = 0; j < len; j++) {
		dst[j] = buf[len-1-j];
	}
	dst[len++] = 'h';
	*str_len += len;
	return r;
}

static ErrorCode
str_append_str(char *str, u32 *str_len, u32 str_cap, char *s, u32 len) {
	ErrorCode r;
	r = ERR_OK;
	if (str_cap - *str_len < len) {
		return ERR_str_LIMIT;
	}
	memcpy(&str[(*str_len)], s, len);
	*str_len += len;
	return r;
}


static ErrorCode
str_append_operand(char *str, u32 *str_len, u32 str_cap, Operand op) {
	ErrorCode r;
	char *cstr;
	u32 displacement;

	r = ERR_OK;

	switch(op.kind) {
		case OPERAND_REG: {
			cstr = registers_to_cstr[op.reg.reg-1];
			r = str_append_str(str, str_len, str_cap, cstr, (u32)strlen(cstr));
			if (r != ERR_OK) return r;
		} break;
		case OPERAND_SEGREG: {
			cstr = segment_registers_to_cstr[op.segreg.segreg-1];
			r = str_append_str(str, str_len, str_cap, cstr, (u32)strlen(cstr));
			if (r != ERR_OK) return r;			
		} break;
		case OPERAND_IMM: {
			r = str_append_u32_as_dec(str, str_len, str_cap, op.imm.imm);
			if (r != ERR_OK) return r;
		} break;
		case OPERAND_MEM: {
			r = str_append_str(str, str_len, str_cap, "[", 1);
			if (r != ERR_OK) return r;
			if (op.memea.memea.base != REG_NONE) {
				cstr = registers_to_cstr[op.memea.memea.base-1];
				r = str_append_str(str, str_len, str_cap, cstr, (u32)strlen(cstr));
				if (r != ERR_OK) return r;
				if (op.memea.memea.index != REG_NONE) {
					r = str_append_str(str, str_len, str_cap, "+", 1);
					if (r != ERR_OK) return r;
					cstr = registers_to_cstr[op.memea.memea.index-1];
					r = str_append_str(str, str_len, str_cap, cstr, (u32)strlen(cstr));
					if (r != ERR_OK) return r;
				}
				if (op.memea.memea.has_disp) {
					cstr = op.memea.memea.disp > 0 ? "+" : "-";
					r = str_append_str(str, str_len, str_cap, cstr, 1);
					if (r != ERR_OK) return r;
					if (op.memea.memea.disp < 0) {
						displacement = (u32)(-(i32)op.memea.memea.disp);
					} else {
						displacement = (u32)op.memea.memea.disp;
					}
					r = str_append_u32_as_dec(str, str_len, str_cap, displacement);
					if (r != ERR_OK) return r;
				}
			} else {
				if (op.memea.memea.has_disp) {
					r = str_append_u32_as_dec(str, str_len, str_cap, (u32)op.memea.memea.disp);
					if (r != ERR_OK) return r;
				} else if (op.memea.memea.has_address) {
					r = str_append_u32_as_hex(str, str_len, str_cap, op.memea.memea.address);
					if (r != ERR_OK) return r;
				}
			}
			r = str_append_str(str, str_len, str_cap, "]", 1);
			if (r != ERR_OK) return r;
		} break;
		case OPERAND_NONE: {
			r = str_append_str(str, str_len, str_cap, "OPERAND_NONE", sizeof("OPERAND_NONE")-1);
			if (r != ERR_OK) return r;
		} break;
		default:
			r = str_append_str(str, str_len, str_cap, "UNIMPLEMENTED", sizeof("UNIMPLEMENTED")-1);
			if (r != ERR_OK) return r;
	}
	return r;
}

/* TODO: Simplify printing */
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

		r = str_append_str(str, &str_len, str_cap, cstr, (u32)strlen(cstr));
		if (r != ERR_OK) return r;

		if (instr.operand_count > 0) {
			r = str_append_str(str, &str_len, str_cap, " ", 1);
			if (r != ERR_OK) return r;

			if (instr.operands[0].kind == OPERAND_MEM && instr.operands[1].kind == OPERAND_IMM) {
				cstr = instr.width == WIDTH8 ? "byte" : "word";
				r = str_append_str(str, &str_len, str_cap, cstr, (u32)strlen(cstr));
				if (r != ERR_OK) return r;
			}
			r = str_append_str(str, &str_len, str_cap, " ", 1);
			if (r != ERR_OK) return r;

			r = str_append_operand(str, &str_len, str_cap, instr.operands[0]);
			if (r != ERR_OK) return r;

			if (instr.operand_count > 1) {
				r = str_append_str(str, &str_len, str_cap, ", ", 2);
				if (r != ERR_OK) return r;
				r = str_append_operand(str, &str_len, str_cap, instr.operands[1]);
				if (r != ERR_OK) return r;
			}
		}
		r = str_append_str(str, &str_len, str_cap, "\n", 1);
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
