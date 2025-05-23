// Examples of quick hash tables and dynamic arrays in C
// https://nullprogram.com/blog/2025/01/19/
// This is free and unencumbered software released into the public domain.
#include <assert.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define new(a, n, t) (t *)alloc(a, n, sizeof(t), _Alignof(t))
#define countof(a) ((ptrdiff_t)(sizeof(a) / sizeof(*(a))))
#define S(s) (Str){s, sizeof(s) - 1}

typedef struct {
	char *beg;
	char *end;
} Arena;

void *alloc(Arena *a, ptrdiff_t count, ptrdiff_t size, ptrdiff_t align) {
	ptrdiff_t pad = -(uintptr_t)a->beg & (align - 1);
	assert(count < (a->end - a->beg - pad) / size); // TODO: OOM policy
	void *r = a->beg + pad;
	a->beg += pad + count * size;
	return memset(r, 0, count * size);
}

typedef struct {
	char *data;
	ptrdiff_t len;
} Str;

Str copy(Arena *a, Str s) {
	Str r = s;
	r.data = new (a, s.len, char);
	if (r.len)
		memcpy(r.data, s.data, r.len);
	return r;
}

Str concat(Arena *a, Str head, Str tail) {
	if (!head.data || head.data + head.len != a->beg) {
		head = copy(a, head);
	}
	head.len += copy(a, tail).len;
	return head;
}

_Bool equals(Str a, Str b) {
	if (a.len != b.len) {
		return 0;
	}
	return !a.len || !memcmp(a.data, b.data, a.len);
}

uint64_t hash64(Str s) {
	uint64_t h = 0x100;
	for (ptrdiff_t i = 0; i < s.len; i++) {
		h ^= s.data[i] & 255;
		h *= 1111111111111111111;
	}
	return h;
}

Str print(Arena *a, char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	ptrdiff_t cap = a->end - a->beg;
	ptrdiff_t len = vsnprintf(a->beg, cap, fmt, ap);
	va_end(ap);

	Str r = {0};
	if (len < 0 || len >= cap) {
		return r; // TODO: trigger OOM
	}
	r.data = a->beg;
	r.len = len;
	a->beg += r.len;
	return r;
}

// Slice (push)

// Evalutes S many times and A possibly zero times.
#define push(a, s)                                                             \
((s)->len == (s)->cap                                                        \
	? (s)->data = push_((a), (s)->data, &(s)->cap, sizeof(*(s)->data)),         \
	(s)->data + (s)->len++ : (s)->data + (s)->len++)

void *push_(Arena *a, void *data, ptrdiff_t *pcap, ptrdiff_t size) {
	ptrdiff_t cap = *pcap;
	ptrdiff_t align = _Alignof(void *);

	if (!data || a->beg != (char *)data + cap * size) {
		void *copy = alloc(a, cap, size, align); // copy to bump pointer
		if (data)
			memcpy(copy, data, cap * size);
		data = copy;
	}

	ptrdiff_t extend = cap ? cap : 4;
	alloc(a, extend, size, align); // grow the backing buffer
	*pcap = cap + extend;
	return data;
}

typedef struct {
	Str *data;
	ptrdiff_t len;
	ptrdiff_t cap;
} StrSlice;

void push_demo(Arena scratch) {
	StrSlice words = {0};
	for (int i = 0; i < 256; i++) {
		Str word = print(&scratch, "word%d", i);
		*push(&scratch, &words) = word;
	}

	Str element = words.data[100];
	printf("%.*s\n", (int)element.len, element.data);
}

// Slice (append)

StrSlice clone(Arena *a, StrSlice s) {
	StrSlice r = {0};
	r.len = r.cap = s.len;
	r.data = new (a, s.len, Str);
	for (ptrdiff_t i = 0; i < s.len; i++) {
		r.data[i] = s.data[i];
	}
	return r;
}

StrSlice append(Arena *a, StrSlice s, Str v) {
	if (s.len == s.cap) {
		if (!s.data || (void *)(s.data + s.len) != a->beg) {
			s = clone(a, s); // copy to bump pointer
		}
		ptrdiff_t extend = s.cap ? s.cap : 4;
		new (a, extend, Str); // grow the backing buffer
		s.cap += extend;
	}
	s.data[s.len++] = v;
	return s;
}

void append_demo(Arena scratch) {
	StrSlice words = {0};
	for (int i = 0; i < 256; i++) {
		Str word = print(&scratch, "word%d", i);
		words = append(&scratch, words, word);
	}

	Str element = words.data[100];
	printf("%.*s\n", (int)element.len, element.data);
}

// MSI

enum { ENVEXP = 10 }; // support up to 1,000 unique keys
typedef struct {
	Str keys[1 << ENVEXP];
	Str vals[1 << ENVEXP];
} FlatEnv;

Str *flatlookup(FlatEnv *env, Str key) {
	uint64_t hash = hash64(key);
	uint32_t mask = (1 << ENVEXP) - 1;
	uint32_t step = (uint32_t)(hash >> (64 - ENVEXP)) | 1;
	for (int32_t i = (int32_t)hash;;) {
		i = (i + step) & mask;
		if (!env->keys[i].data) {
			env->keys[i] = key;
			return env->vals + i;
		} else if (equals(env->keys[i], key)) {
			return env->vals + i;
		}
	}
}

char **flat_to_envp(FlatEnv *env, Arena *a) {
	int cap = 1 << ENVEXP;
	char **envp = new (a, cap, char *);
	int len = 0;
	for (int i = 0; i < cap; i++) {
		if (env->vals[i].data) {
			Str pair = env->keys[i];
			pair = concat(a, pair, S("="));
			pair = concat(a, pair, env->vals[i]);
			pair = concat(a, pair, S("\0"));
			envp[len++] = pair.data;
		}
	}
	return envp;
}

void msi_demo(Arena scratch) {
	FlatEnv *env = new (&scratch, 1, FlatEnv);

	for (int i = 0; i < 256; i++) {
		Str key = print(&scratch, "key%d", i);
		Str value = print(&scratch, "value%d", i);
		*flatlookup(env, key) = value;
	}

	Str value = *flatlookup(env, S("key100"));
	printf("%.*s\n", (int)value.len, value.data);
}

// Hash Trie

typedef struct Env Env;
struct Env {
	Env *child[4];
	Str key;
	Str value;
};

Str *lookup(Env **env, Str key, Arena *a) {
	for (uint64_t h = hash64(key); *env; h <<= 2) {
		if (equals(key, (*env)->key)) {
			return &(*env)->value;
		}
		env = &(*env)->child[h >> 62];
	}
	if (!a)
		return 0;
	*env = new (a, 1, Env);
	(*env)->key = key;
	return &(*env)->value;
}

typedef struct {
	char **data;
	ptrdiff_t len;
	ptrdiff_t cap;
} EnvpSlice;

EnvpSlice env_to_envp_(EnvpSlice r, Env *env, Arena *a) {
	if (env) {
		Str pair = env->key;
		pair = concat(a, pair, S("="));
		pair = concat(a, pair, env->value);
		pair = concat(a, pair, S("\0"));
		*push(a, &r) = pair.data;
		for (int i = 0; i < countof(env->child); i++) {
			r = env_to_envp_(r, env->child[i], a);
		}
	}
	return r;
}

char **env_to_envp(Env *env, Arena *a) {
	EnvpSlice r = {0};
	r = env_to_envp_(r, env, a);
	push(a, &r);
	return r.data;
}

char **env_to_envp_safe(Env *env, Arena *a) {
	EnvpSlice r = {0};

	typedef struct {
		Env *env;
		int index;
	} Frame;
	Frame init[16]; // small size optimization

	struct {
		Frame *data;
		ptrdiff_t len;
		ptrdiff_t cap;
	} stack = {init, 0, countof(init)};

	*push(a, &stack) = (Frame){env, 0};
	while (stack.len) {
		Frame *top = stack.data + stack.len - 1;

		if (!top->env) {
			stack.len--;

		} else if (top->index == countof(top->env->child)) {
			Str pair = top->env->key;
			pair = concat(a, pair, S("="));
			pair = concat(a, pair, top->env->value);
			pair = concat(a, pair, S("\0"));
			*push(a, &r) = pair.data;
			stack.len--;

		} else {
			int i = top->index++;
			*push(a, &stack) = (Frame){top->env->child[i], 0};
		}
	}

	push(a, &r);
	return r.data;
}

void hashtrie_demo(Arena scratch) {
	Env *env = 0;

	for (int i = 0; i < 256; i++) {
		Str key = print(&scratch, "key%d", i);
		Str value = print(&scratch, "value%d", i);
		*lookup(&env, key, &scratch) = value;
	}

	Str value = *lookup(&env, S("key100"), 0);
	printf("%.*s\n", (int)value.len, value.data);
}

/////////////////////////////////////////////////////////////

// TODO: Printing procedure for STATUS report
enum Status {
	OK,
	FAIL,
	FAIL_FILE_BINARY_READ,
	FAIL_FILE_OPEN,
	FAIL_DECODE_ILLEGAL_OPCODE,
	FAIL_PRINT_UKNOWN_OPCODE,
};

enum Status read_binary_file(Arena *a, const char *filename,
			     uint8_t **out_buffer, ptrdiff_t *out_len) {
	FILE *file = fopen(filename, "rb");
	if (!file) {
		return FAIL_FILE_OPEN;
	}

	fseek(file, 0, SEEK_END);
	size_t file_size = ftell(file);
	fseek(file, 0, SEEK_SET);

	uint8_t *buffer = new (a, file_size, unsigned char);

	size_t bytes_read = fread(buffer, sizeof(*buffer), file_size, file);
	if (bytes_read != file_size) {
		return FAIL_FILE_BINARY_READ;
	}

	*out_buffer = buffer;
	*out_len = bytes_read;

	return OK;
}

enum Status dump(StrSlice *out) {
	for (int i = 0; i < out->len; i++) {
		printf("%.*s\n", (int)out->data[i].len, out->data[i].data);
	}
	return OK;
}

/* enum Status write_binary_file(const char* filename, uint8_t* data, ptrdiff_t
 * len) { */
/*      FILE* file = fopen(filename, "rb"); */
/*      if (!file) { */
/*              return FAIL_FILE_OPEN; */
/*      } */
/*      size_t count = fwrite(data, sizeof(*data), len, file); */
/*      if (count != len) { */
/*              return FAIL_FILE_BINARY_WRITE; */
/*      } */
/*      return OK; */
/* } */

typedef struct {
	uint8_t *data;
	ptrdiff_t len;
	ptrdiff_t at;
} CodeStream;

#include "opcodes.h"

typedef struct {
	Instruction *data;
	ptrdiff_t len;
	ptrdiff_t cap;
} InstructionSlice;

static enum Status print_instructions(Arena *a, InstructionSlice *in,
				      StrSlice *out) {
	*push(a, out) = print(a, "bits 16\n");

	for (int32_t i = 0; i < in->len; i++) {
		Instruction instr = in->data[i];
		switch (instr.opcode) {
			default:
				return FAIL_PRINT_UKNOWN_OPCODE;
			case OPCODE_MOV8_RM_REG:
			case OPCODE_MOV16_RM_REG:
			case OPCODE_MOV8_REG_RM:
			case OPCODE_MOV16_REG_RM: {
				Str src = S(register_names[instr.reg + (instr.wide * 8)]);
				Str dst = {0};
				if (instr.mod == 0b11) {
					dst = S(register_names[instr.rm + (instr.wide * 8)]);
				} else {
					if (instr.rm == 0b110 && instr.mod == 0b00) {
						dst = print(a, "[%d]", instr.direct_address);
					} else {
						if (instr.rm == 0b000) {
							dst = S("[bx + si");
						} else if (instr.rm == 0b001) {
							dst = S("[bx + di");
						} else if (instr.rm == 0b010) {
							dst = S("[bp + si");
						} else if (instr.rm == 0b011) {
							dst = S("[bp + di");
						} else if (instr.rm == 0b100) {
							dst = S("[si");
						} else if (instr.rm == 0b101) {
							dst = S("[di");
						} else if (instr.rm == 0b110) {
							dst = S("[bp");
						} else if (instr.rm == 0b111) {
							dst = S("[bx");
						}
						if (instr.mod == 0b00) {
							dst = print(a, "%.*s]", dst.len, dst.data);
						} else {
							if (instr.disp > 0) {
								dst = print(a, "%.*s + %d]", dst.len, dst.data, instr.disp);
							} else if (instr.disp < 0) {
								dst = print(a, "%.*s - %d]", dst.len, dst.data, -instr.disp);
							} else {
								dst = print(a, "%.*s]", dst.len, dst.data);
							}
						}
					}
				}
				if (instr.direction == 1) {
					Str tmp = src;
					src = dst;
					dst = tmp;
				}
				*push(a, out) =
					print(a, "mov %.*s, %.*s", dst.len, dst.data, src.len, src.data);
			} break;

			case OPCODE_ADD8_RM_REG:
			case OPCODE_ADD16_RM_REG:
			case OPCODE_ADD8_REG_RM:
			case OPCODE_ADD16_REG_RM: {
				Str src = S(register_names[instr.reg + (instr.wide * 8)]);
				Str dst = {0};
				if (instr.mod == 0b11) {
					dst = S(register_names[instr.rm + (instr.wide * 8)]);
				} else {
					if (instr.rm == 0b110 && instr.mod == 0b00) {
						dst = print(a, "[%d]", instr.direct_address);
					} else {
						if (instr.rm == 0b000) {
							dst = S("[bx + si");
						} else if (instr.rm == 0b001) {
							dst = S("[bx + di");
						} else if (instr.rm == 0b010) {
							dst = S("[bp + si");
						} else if (instr.rm == 0b011) {
							dst = S("[bp + di");
						} else if (instr.rm == 0b100) {
							dst = S("[si");
						} else if (instr.rm == 0b101) {
							dst = S("[di");
						} else if (instr.rm == 0b110) {
							dst = S("[bp");
						} else if (instr.rm == 0b111) {
							dst = S("[bx");
						}
						if (instr.mod == 0b00) {
							dst = print(a, "%.*s]", dst.len, dst.data);
						} else {
							if (instr.disp > 0) {
								dst = print(a, "%.*s + %d]", dst.len, dst.data, instr.disp);
							} else if (instr.disp < 0) {
								dst = print(a, "%.*s - %d]", dst.len, dst.data, -instr.disp);
							} else {
								dst = print(a, "%.*s]", dst.len, dst.data);
							}
						}
					}
				}
				if (instr.direction == 1) {
					Str tmp = src;
					src = dst;
					dst = tmp;
				}
				*push(a, out) =
					print(a, "add %.*s, %.*s", dst.len, dst.data, src.len, src.data);
			} break;

			case OPCODE_MOV8_AL_IMM:
			case OPCODE_MOV8_CL_IMM:
			case OPCODE_MOV8_DL_IMM:
			case OPCODE_MOV8_BL_IMM:
			case OPCODE_MOV8_AH_IMM:
			case OPCODE_MOV8_CH_IMM:
			case OPCODE_MOV8_DH_IMM:
			case OPCODE_MOV8_BH_IMM:
			case OPCODE_MOV16_AX_IMM:
			case OPCODE_MOV16_CX_IMM:
			case OPCODE_MOV16_DX_IMM:
			case OPCODE_MOV16_BX_IMM:
			case OPCODE_MOV16_SP_IMM:
			case OPCODE_MOV16_BP_IMM:
			case OPCODE_MOV16_SI_IMM:
			case OPCODE_MOV16_DI_IMM: {
				Str dst = S(register_names[instr.reg + (instr.wide * 8)]);
				Str src = print(a, "%d", instr.imm);
				*push(a, out) =
					print(a, "mov %.*s, %.*s", dst.len, dst.data, src.len, src.data);
			} break;
			case OPCODE_MOV8_MEM_IMM:
			case OPCODE_MOV16_MEM_IMM: {
				Str src = {0};
				if (instr.wide) {
					src = S("word");
				} else {
					src = S("byte");
				}
				src = print(a, "%.*s %d", src.len, src.data, instr.imm);

				// NOTE(Refactoring): Candidate for reusing
				Str dst = {0};
				if (instr.mod == 0b11) {
					dst = S(register_names[instr.rm + (instr.wide * 8)]);
				} else {
					if (instr.rm == 0b110 && instr.mod == 0b00) {
						dst = print(a, "[%d]", instr.direct_address);
					} else {
						if (instr.rm == 0b000) {
							dst = S("[bx + si");
						} else if (instr.rm == 0b001) {
							dst = S("[bx + di");
						} else if (instr.rm == 0b010) {
							dst = S("[bp + si");
						} else if (instr.rm == 0b011) {
							dst = S("[bp + di");
						} else if (instr.rm == 0b100) {
							dst = S("[si");
						} else if (instr.rm == 0b101) {
							dst = S("[di");
						} else if (instr.rm == 0b110) {
							dst = S("[bp");
						} else if (instr.rm == 0b111) {
							dst = S("[bx");
						}
						if (instr.mod == 0b00) {
							dst = print(a, "%.*s]", dst.len, dst.data);
						} else {
							if (instr.disp > 0) {
								dst = print(a, "%.*s + %d]", dst.len, dst.data, instr.disp);
							} else if (instr.disp < 0) {
								dst = print(a, "%.*s - %d]", dst.len, dst.data, -instr.disp);
							} else {
								dst = print(a, "%.*s]", dst.len, dst.data);
							}
						}
					}
				}
				*push(a, out) =
					print(a, "mov %.*s, %.*s", dst.len, dst.data, src.len, src.data);
			} break;
			case OPCODE_ADD8_ACC_IMM:
			case OPCODE_ADD16_ACC_IMM: {
				Str dst = S(register_names[instr.reg + (instr.wide * 8)]);
				Str src = print(a, "%d", instr.imm);
				*push(a, out) =
					print(a, "add %.*s, %.*s", dst.len, dst.data, src.len, src.data);
			} break;

			case OPCODE_ADD_MEM8_IMM8:
			case OPCODE_ADD_MEM16_IMM16:
			case OPCODE_ADD_MEM8_IMM8_XXXXXX: // NOTE: The same as OPCODE_ADD_MEM8_IMM8 ???
			case OPCODE_ADD_MEM16_IMM8: {
				Str src = {0};
				if (instr.wide) {
					src = S("word");
				} else {
					src = S("byte");
				}
				src = print(a, "%.*s %d", src.len, src.data, instr.imm);

				// NOTE(Refactoring): Candidate for reusing
				Str dst = {0};
				if (instr.mod == 0b11) {
					dst = S(register_names[instr.rm + (instr.wide * 8)]);
				} else {
					if (instr.rm == 0b110 && instr.mod == 0b00) {
						dst = print(a, "[%d]", instr.direct_address);
					} else {
						if (instr.rm == 0b000) {
							dst = S("[bx + si");
						} else if (instr.rm == 0b001) {
							dst = S("[bx + di");
						} else if (instr.rm == 0b010) {
							dst = S("[bp + si");
						} else if (instr.rm == 0b011) {
							dst = S("[bp + di");
						} else if (instr.rm == 0b100) {
							dst = S("[si");
						} else if (instr.rm == 0b101) {
							dst = S("[di");
						} else if (instr.rm == 0b110) {
							dst = S("[bp");
						} else if (instr.rm == 0b111) {
							dst = S("[bx");
						}
						if (instr.mod == 0b00) {
							dst = print(a, "%.*s]", dst.len, dst.data);
						} else {
							if (instr.disp > 0) {
								dst = print(a, "%.*s + %d]", dst.len, dst.data, instr.disp);
							} else if (instr.disp < 0) {
								dst = print(a, "%.*s - %d]", dst.len, dst.data, -instr.disp);
							} else {
								dst = print(a, "%.*s]", dst.len, dst.data);
							}
						}
					}
				}
				*push(a, out) =
					print(a, "add %.*s, %.*s", dst.len, dst.data, src.len, src.data);
			} break;
			case OPCODE_MOV8_AL_MEM:
			case OPCODE_MOV16_AX_MEM:
			case OPCODE_MOV8_MEM_AL:
			case OPCODE_MOV16_MEM_AX: {
				Str src = print(a, "[%d]", instr.direct_address);
				Str dst = S(register_names[instr.reg]);
				if (instr.direction == 1) {
					Str tmp = src;
					src = dst;
					dst = tmp;
				}
				*push(a, out) =
					print(a, "mov %.*s, %.*s", dst.len, dst.data, src.len, src.data);
			} break;
		}
	}
	return OK;
}

static void decode_instr_mov_accum_mem(Arena *a, CodeStream *stream, Instruction *instr) {
	uint8_t b0 = stream->data[stream->at++];
	instr->opcode = b0;
	instr->wide = b0 & 0b1;
	instr->direction = (b0 >> 1) & 0b1;
	if (instr->opcode == OPCODE_MOV8_MEM_AL ||
		instr->opcode == OPCODE_MOV8_AL_MEM) {
		instr->reg = Reg_AL;
	} else if (instr->opcode == OPCODE_MOV16_MEM_AX ||
		instr->opcode == OPCODE_MOV16_AX_MEM) {
		instr->reg = Reg_AX;
	} else {
	}

	instr->direct_address = stream->data[stream->at++];
	instr->direct_address = (stream->data[stream->at++] << 8) | (instr->direct_address);
}


static void decode_instr_mov_rm_reg(Arena *a, CodeStream *stream,
				    Instruction *instr) {
	uint8_t b0 = stream->data[stream->at++];
	instr->opcode = b0;
	instr->wide = b0 & 0b1;
	instr->direction = (b0 >> 1) & 0b1;

	uint8_t b1 = stream->data[stream->at++];
	int32_t mod = (b1 >> 6) & 0b11;
	int32_t reg = (b1 >> 3) & 0b111;
	int32_t rm = b1 & 0b111;
	instr->mod = mod;
	instr->reg = reg;
	instr->rm = rm;

	if (mod == 0b00 && rm == 0b110) {
		instr->direct_address = stream->data[stream->at++];
		instr->direct_address =
			(stream->data[stream->at++] << 8) | (instr->direct_address);
	} else if (mod == 0b01) {
		// TODO: somewhat ugly
		memcpy((uint8_t*)&instr->disp, &stream->data[stream->at], 1);
		stream->at++;
		if ((int8_t)(((uint8_t*)&instr->disp)[0]) < 0) {
			((uint8_t*)&instr->disp)[1] = 0xFF;
		}
	} else if (mod == 0b10) {
		memcpy((uint8_t*)&instr->disp, &stream->data[stream->at], 2);
		stream->at += 2;
	}

	// DEBUG PRINT
	//  if (instr->reg == Reg_DX) {
	 printf("; INSTRUCTION OPCODE: %x\n", instr->opcode); 
	 printf("; INSTRUCTION MOD: %x\n", instr->mod); 
	 printf("; INSTRUCTION RM: %x\n", instr->rm); 
	 printf("; INSTRUCTION reg: %x\n", instr->reg); 
	 printf("; INSTRUCTION disp: %d\n", instr->disp); 
	 printf("; INSTRUCTION NEG disp: %d\n", -instr->disp); 
	//  }
	//
}

static void decode_instr_mov_mem_imm(Arena *a, CodeStream *stream,
				     Instruction *instr) {
	uint8_t b0 = stream->data[stream->at++];
	instr->opcode = b0;
	instr->wide = b0 & 0b1;

	uint8_t b1 = stream->data[stream->at++];
	int32_t mod = (b1 >> 6) & 0b11;
	int32_t rm = b1 & 0b111;
	instr->mod = mod;
	instr->rm = rm;

	if (mod == 0b00 && rm == 0b110) {
		instr->direct_address = stream->data[stream->at++];
		instr->direct_address =
			(stream->data[stream->at++] << 8) | (instr->direct_address);
	} else if (mod == 0b01) {
		memcpy((uint8_t*)&instr->disp, &stream->data[stream->at], 1);
		stream->at++;
		// TODO: somewhat ugly
		if ((int8_t)(((uint8_t*)&instr->disp)[0]) < 0) {
			((uint8_t*)&instr->disp)[1] = 0xFF;
		}
	} else if (mod == 0b10) {
		memcpy((uint8_t*)&instr->disp, &stream->data[stream->at], 2);
		stream->at += 2;
	}

	if (instr->wide) {
		instr->imm = stream->data[stream->at++];
		instr->imm = (int16_t)(stream->data[stream->at++] << 8) | instr->imm;
	} else {
		instr->imm = stream->data[stream->at++];
	}
}

static void decode_instr_add_mem_imm(Arena* a, CodeStream* stream,
				     Instruction* instr) {
	uint8_t b0 = stream->data[stream->at++];
	instr->opcode = b0;
	instr->wide = b0 & 0b1;
	instr->sign_extend = b0 & 0b10;

	uint8_t b1 = stream->data[stream->at++];
	int32_t mod = (b1 >> 6) & 0b11;
	int32_t rm = b1 & 0b111;
	instr->mod = mod;
	instr->rm = rm;

	if (mod == 0b00 && rm == 0b110) {
		instr->direct_address = stream->data[stream->at++];
		instr->direct_address =
			(stream->data[stream->at++] << 8) | (instr->direct_address);
	} else if (mod == 0b01) {
		memcpy((uint8_t*)&instr->disp, &stream->data[stream->at], 1);
		stream->at++;
		// TODO: somewhat ugly
		if ((int8_t)(((uint8_t*)&instr->disp)[0]) < 0) {
			((uint8_t*)&instr->disp)[1] = 0xFF;
		}
	} else if (mod == 0b10) {
		memcpy((uint8_t*)&instr->disp, &stream->data[stream->at], 2);
		stream->at += 2;
	}

	if (instr->wide) {
		if (instr->sign_extend) {
			memcpy((uint8_t*)&instr->imm, &stream->data[stream->at], 1);
			stream->at++;
			// TODO: somewhat ugly
			if ((int8_t)(((uint8_t*)&instr->imm)[0]) < 0) {
				((uint8_t*)&instr->imm)[1] = 0xFF;
			}
		} else {
			memcpy((uint8_t*)&instr->imm, &stream->data[stream->at], 2);
			stream->at += 2;
		}
	} else {
		if (instr->sign_extend) {
			memcpy((uint8_t*)&instr->imm, &stream->data[stream->at], 1);
			stream->at++;
			// TODO: somewhat ugly
			if ((int8_t)(((uint8_t*)&instr->imm)[0]) < 0) {
				((uint8_t*)&instr->imm)[1] = 0xFF;
			}
		} else {
			memcpy((uint8_t*)&instr->imm, &stream->data[stream->at], 1);
			stream->at++;
			// TODO: somewhat ugly
			if ((int8_t)(((uint8_t*)&instr->imm)[0]) < 0) {
				((uint8_t*)&instr->imm)[1] = 0x00;
			}
		}
	}
}

static void decode_instr_add_acc_imm(Arena* a, CodeStream* stream,
				     Instruction* instr) {
	uint8_t b0 = stream->data[stream->at++];
	instr->opcode = b0;
	instr->wide = b0 & 0b1;
	instr->direction = 1;

	if (instr->wide) {
		/*instr->imm = stream->data[stream->at++];*/
		/*instr->imm = (int16_t)(stream->data[stream->at++] << 8) | instr->imm;*/
		memcpy((uint8_t*)&instr->imm, &stream->data[stream->at], 2);
		stream->at += 2;
	} else {
		instr->imm = stream->data[stream->at++];
	}
}

static void decode_instr_mov_reg_imm(Arena *a, CodeStream* stream,
				     Instruction* instr) {
	uint8_t b0 = stream->data[stream->at++];
	instr->opcode = b0;
	instr->wide = (b0 >> 3) & 0b1;
	instr->reg = b0 & 0b111;
	instr->direction = 1;

	if (instr->wide) {
		instr->imm = stream->data[stream->at++];
		instr->imm = (int16_t)(stream->data[stream->at++] << 8) | instr->imm;
	} else {
		instr->imm = stream->data[stream->at++];
	}
}


static void decode_instr_add_rm_reg(Arena *a, CodeStream* stream,
				    Instruction* instr) {
	decode_instr_mov_rm_reg(a, stream, instr);
}

//
// Define the function pointer type
typedef enum Status (*DecoderFunc)(Arena* a, CodeStream* stream, Instruction* instr);
static DecoderFunc decoder_table[256] = {0};

void decode_default(Arena* a, CodeStream* stream, Instruction* instr) {
	// printf("NOT IMPLEMENTED: [%x]\n", stream->data[stream->at]);
	// Assume that instr is zero initialized, so just push it and later print as NOT IMPLEMENTED
	*push(a, out) = instr;
}

static void extract_wideness_and_direction_0(Instruction* instr, CodeStream* stream) {
	uint8_t byte = stream->data[stream->at++];
	instr->wide = byte & 0b1;
	instr->direction = (byte >> 1) & 0b1;
}

static void extract_wideness(Instruction* instr, CodeStream* stream) {
	uint8_t byte = stream->data[stream->at++];
	instr->wide = byte & 0b1;
}

static void extract_wideness_and_signextend(Instruction* instr, CodeStream* stream) {
	uint8_t byte = stream->data[stream->at++];
	instr->wide = byte & 0b1;
	instr->sign_extend = (byte >> 1) & 0b1;
}

static void extract_mod_reg_rm_0(Instruction* instr, CodeStream* stream) {
	uint8_t byte = stream->data[stream->at++];
	int32_t mod = (byte >> 6) & 0b11;
	int32_t reg = (byte >> 3) & 0b111;
	int32_t rm = byte & 0b111;
	instr->mod = mod;
	instr->reg = reg;
	instr->rm = rm;
}

static void extract_direct_address_0(Instruction* instr, CodeStream* stream) {
	instr->direct_address = stream->data[stream->at++];
	instr->direct_address = (stream->data[stream->at++] << 8) | (instr->direct_address);
}

static void extract_displacement_u8(Instruction* instr, CodeStream* stream) {
	// TODO: somewhat ugly
	memcpy((uint8_t*)&instr->disp, &stream->data[stream->at], 1);
	stream->at++;
	if ((int8_t)(((uint8_t*)&instr->disp)[0]) < 0) {
		((uint8_t*)&instr->disp)[1] = 0xFF;
	}
}

static void extract_displacement_u16(Instruction* instr, CodeStream* stream) {
	// TODO: somewhat ugly
	memcpy((uint8_t*)&instr->disp, &stream->data[stream->at], 2);
	stream->at += 2;
}


static void extract_imm(Instruction* instr, CodeStream* stream) {
	// TODO: make it not ugly
	if (instr->wide) {
		if (instr->sign_extend) {
			memcpy((uint8_t*)&instr->imm, &stream->data[stream->at], 1);
			stream->at++;
			if ((int8_t)(((uint8_t*)&instr->imm)[0]) < 0) {
				((uint8_t*)&instr->imm)[1] = 0xFF;
			}
		} else {
			memcpy((uint8_t*)&instr->imm, &stream->data[stream->at], 2);
			stream->at += 2;
		}
	} else {
		if (instr->sign_extend) {
			memcpy((uint8_t*)&instr->imm, &stream->data[stream->at], 1);
			stream->at++;
			if ((int8_t)(((uint8_t*)&instr->imm)[0]) < 0) {
				((uint8_t*)&instr->imm)[1] = 0xFF;
			}
		} else {
			memcpy((uint8_t*)&instr->imm, &stream->data[stream->at], 1);
			stream->at++;
			if ((int8_t)(((uint8_t*)&instr->imm)[0]) < 0) {
				((uint8_t*)&instr->imm)[1] = 0x00;
			}
		}
	}
}

static void extract_imm_with_signextend(Instruction* instr, CodeStream* stream) {

}

static void extract_stream_slice(Instruction* instr, CodeStream* stream, ptrdiff_t beg) {
	instr->data = &stream->data[beg];
	instr->len = stream->at - beg;	
}

void decode_0x00_0x01_0x02_0x03(Arena* a, CodeStream* stream, Instruction* instr) {
	ptrdiff_t beg = stream->at;
	extract_wideness_and_direction_0(instr, stream);
	extract_mod_reg_rm_0(instr, stream);
	if (mod == 0b00 && rm == 0b110) {
		extract_direct_address(instr, stream);
	} else if (mod == 0b01) {
		extract_displacement_u8(instr, stream);
	} else if (mod == 0b10) {
		extract_displacement_u16(instr, stream);
	}
	extract_slice(instr, stream, beg);

	// Maybe no need to compute instruction name here
	// It needed when executing and printing instruction, so compute name there
	if (instr->d) {
		if (instr->w) {
			instr->name = INSTR_ADD_REG16_REGMEM16;
		} else {
			instr->name = INSTR_ADD_REG8_REGMEM8;
		}
	} else {
		if (instr->w) {
			instr->name = INSTR_ADD_REGMEM16_REG16;
		} else {
			instr->name = INSTR_ADD_REGMEM8_REG8;
		}		
	}
}

void decode_0x04_0x05(Arena* a, CodeStream* stream, Instruction* instr) {
	ptrdiff_t beg = stream->at;
	extract_wideness(instr, stream);
	extract_imm(instr, stream);
	extract_slice(instr, stream, beg);
	if (instr->wide) {
		instr->name = INSTR_ADD_ACC16_IMM;
	} else {
		instr->name = INSTR_ADD_ACC8_IMM;
	}
}

// 0x80_0x81_0x82_0x83
// ADD, ADC, SUB, SBB, CMP, OR, AND, XOR
void decode_0x80_0x81_0x82_0x83(Arena* a, CodeStream* stream, Instruction* instr) {
	ptrdiff_t beg = stream->at;
	extract_wideness_and_signextend(isntr, stream);
	extract_mod_reg_rm_0(instr, stream);
	if (mod == 0b00 && rm == 0b110) {
		extract_direct_address(instr, stream);
	} else if (mod == 0b01) {
		extract_displacement_u8(instr, stream);
	} else if (mod == 0b10) {
		extract_displacement_u16(instr, stream);
	}
	extract_imm(instr, stream);
	extract_slice(instr, stream, beg);
	if (instr->reg == 0b000) {
		if (instr->w) {
			instr->name = INSTR_ADD_REGMEM16_IMM;
		} else {
			instr->name = INSTR_ADD_REGMEM8_IMM;
		}
	} else if (instr->reg == 0b010) {
		if (instr->w) {
			instr->name = INSTR_ADC_REGMEM16_IMM;
		} else {
			instr->name = INSTR_ADC_REGMEM8_IMM;
		}
	} else if (instr->reg == 0b101) {
		if (instr->w) {
			instr->name = INSTR_SUB_REGMEM16_IMM;
		} else {
			instr->name = INSTR_SUB_REGMEM8_IMM;
		}
	} else if (instr->reg == 0b011) {
		if (instr->w) {
			instr->name = INSTR_SBB_REGMEM16_IMM;
		} else {
			instr->name = INSTR_SBB_REGMEM8_IMM;
		}
	} else if (instr->reg == 0b111) {
		if (instr->w) {
			instr->name = INSTR_CMP_REGMEM16_IMM;
		} else {
			instr->name = INSTR_CMP_REGMEM8_IMM;
		}
	} else if (instr->reg == 0b100) {
		if (instr->w) {
			instr->name = INSTR_AND_REGMEM16_IMM;
		} else {
			instr->name = INSTR_AND_REGMEM8_IMM;
		}
	} else if (instr->reg == 0b001) {
		if (instr->w) {
			instr->name = INSTR_OR_REGMEM16_IMM;
		} else {
			instr->name = INSTR_OR_REGMEM8_IMM;
		}
	} else {
		if (instr->w) {
			instr->name = INSTR_XOR_REGMEM16_IMM;
		} else {
			instr->name = INSTR_XOR_REGMEM8_IMM;
		}
	}
}

void init_decoder_table(DecoderFunc* decoder_table, ptrdiff_t size) {
	for (int i = 0; i < size; i++) {
		decoder_table[i] = decode_default;
	}
	decoder_table[0x00] = decode_0x00_0x01_0x02_0x03; // NOTE: Should rename decode_0x00_0x01_0x02_0x03 to decode_add_regmem
	decoder_table[0x01] = decode_0x00_0x01_0x02_0x03;
	decoder_table[0x02] = decode_0x00_0x01_0x02_0x03;
	decoder_table[0x03] = decode_0x00_0x01_0x02_0x03; // :NOTE
	decoder_table[0x04] = decode_0x04_0x05;           // NOTE: Should rename to decode_add_acc_imm
	decoder_table[0x05] = decode_0x04_0x05;

	// ...

	decoder_table[0x80] = decode_0x80_0x81_0x82_0x83; // NOTE: Maybe rename to decode_add_or_adc_sbb_and_sub_xor_cmp
	decoder_table[0x81] = decode_0x80_0x81_0x82_0x83;
	decoder_table[0x82] = decode_0x80_0x81_0x82_0x83;
	decoder_table[0x83] = decode_0x80_0x81_0x82_0x83;
}

enum Status decode2(Arena* a, CodeStream* cs, InstructionSlice* out) {
	for (; cs->at < cs->len;) {
		uint8_t byte = cs->data[cs->at];
		Instruction instr = {};
		DecoderFunc decoder = decoder_table[byte];
		decoder(a, cs, &instr);
		*push(a, out) = instr;
	}
	return OK;
}

//

// Transforms bytes stream into instructions
enum Status decode(Arena *a, CodeStream *cs, InstructionSlice *out) {

	for (; cs->at < cs->len;) {
		uint8_t opcode = cs->data[cs->at];

		Instruction instr = {};
		switch (opcode) {
			default: {
				printf("; ILLLEGAL OPCODE: %d\n", opcode);
				fflush(stdout);
				return FAIL_DECODE_ILLEGAL_OPCODE;
			}
			case OPCODE_MOV8_RM_REG:
			case OPCODE_MOV16_RM_REG:
			case OPCODE_MOV8_REG_RM:
			case OPCODE_MOV16_REG_RM:
				decode_instr_mov_rm_reg(a, cs, &instr);
				break;
			case OPCODE_MOV8_AL_IMM:
			case OPCODE_MOV8_CL_IMM:
			case OPCODE_MOV8_DL_IMM:
			case OPCODE_MOV8_BL_IMM:
			case OPCODE_MOV8_AH_IMM:
			case OPCODE_MOV8_CH_IMM:
			case OPCODE_MOV8_DH_IMM:
			case OPCODE_MOV8_BH_IMM:
			case OPCODE_MOV16_AX_IMM:
			case OPCODE_MOV16_CX_IMM:
			case OPCODE_MOV16_DX_IMM:
			case OPCODE_MOV16_BX_IMM:
			case OPCODE_MOV16_SP_IMM:
			case OPCODE_MOV16_BP_IMM:
			case OPCODE_MOV16_SI_IMM:
			case OPCODE_MOV16_DI_IMM:
				decode_instr_mov_reg_imm(a, cs, &instr);
				break;
			case OPCODE_MOV8_MEM_IMM:
			case OPCODE_MOV16_MEM_IMM:
				decode_instr_mov_mem_imm(a, cs, &instr);
				break;
			case OPCODE_MOV8_AL_MEM:
			case OPCODE_MOV16_AX_MEM:
			case OPCODE_MOV8_MEM_AL:
			case OPCODE_MOV16_MEM_AX:
				decode_instr_mov_accum_mem(a, cs, &instr);
				break;
			case OPCODE_ADD8_RM_REG:
			case OPCODE_ADD16_RM_REG:
			case OPCODE_ADD8_REG_RM:
			case OPCODE_ADD16_REG_RM:
				decode_instr_add_rm_reg(a, cs, &instr);
				break;
			case OPCODE_ADD_MEM8_IMM8:
			case OPCODE_ADD_MEM16_IMM16:
			case OPCODE_ADD_MEM8_IMM8_XXXXXX: // NOTE: The same as OPCODE_ADD_MEM8_IMM8 ???
			case OPCODE_ADD_MEM16_IMM8:
				decode_instr_add_mem_imm(a, cs, &instr);
				break;
			case OPCODE_ADD8_ACC_IMM:
			case OPCODE_ADD16_ACC_IMM: 
				decode_instr_add_acc_imm(a, cs, &instr);
				break;
		}
		*push(a, out) = instr;
	}
	return OK;
}

int main(int argc, char **argv) {
	int cap = 1 << 24;
	char *mem = malloc(cap);
	Arena a = {mem, mem + (cap)};

	if (argc != 2) {
		fprintf(stderr, "Usage: emu8086 ./machine-code\n");
		exit(EXIT_FAILURE);
	}

	CodeStream codestream = {0};

	enum Status status = FAIL;
	status = read_binary_file(&a, argv[1], &codestream.data, &codestream.len);
	if (status != OK) {
		fprintf(stderr, "FAIL STATUS: [%d], when `read_binary_file`.\n", status);
		exit(EXIT_SUCCESS);
	}

	InstructionSlice instructions = {0};
	status = decode(&a, &codestream, &instructions);
	if (status != OK) {
		fprintf(stderr, "FAIL STATUS: [%d], when `decode`.\n", status);
		exit(EXIT_SUCCESS);
	}

	StrSlice printed = {0};
	status = print_instructions(&a, &instructions, &printed);
	if (status != OK) {
		fprintf(stderr, "FAIL STATUS: [%d], when `print_instructions`.\n", status);
		exit(EXIT_SUCCESS);
	}

	status = dump(&printed);
	if (status != OK) {
		fprintf(stderr, "FAIL STATUS: [%d], when `dump`.\n", status);
		exit(EXIT_SUCCESS);
	}

	return OK;
}

/* int main(void) */
/* { */
/*     int   cap = 1<<24; */
/*     char *mem = malloc(cap); */
/*     Arena a   = {mem, mem+(cap)}; */

/*     msi_demo(a); */
/*     hashtrie_demo(a); */
/*     push_demo(a); */
/*     append_demo(a); */
/* } */
