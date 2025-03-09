#include <stdint.h>
#include <stddef.h>

enum InstructionOpcode {
	OPCODE_ADD8_RM_REG     = 0x00,
	OPCODE_ADD16_RM_REG    = 0X01,
	OPCODE_ADD8_REG_RM     = 0X02,
	OPCODE_ADD16_REG_RM    = 0X03,
	OPCODE_ADD8_ACC_IMM         = 0X04,
	OPCODE_ADD16_ACC_IMM        = 0X05,
	OPCODE_PUSH_ES               = 0X06,
	OPCODE_POP_ES                = 0x07,
	OPCODE_OR8_RM_REG      = 0x08,
	OPCODE_OR16_RM_REG     = 0x09,
	OPCODE_OR8_REG_RM      = 0x0A,
	OPCODE_OR16_REG_RM     = 0x0B,
	OPCODE_OR8_AL_IMM           = 0x0C,
	OPCODE_OR16_AX_MEM          = 0x0D,
	OPCODE_PUSH_CS                = 0x0E,

	OPCODE_ADD_MEM8_IMM8 = 0x80,
	OPCODE_ADD_MEM16_IMM16 = 0x81,
	OPCODE_ADD_MEM8_IMM8_XXXXXX = 0x82, // NOTE: The same as OPCODE_ADD_MEM8_IMM8 ???
	OPCODE_ADD_MEM16_IMM8 = 0x83,

	// ...
	OPCODE_MOV8_RM_REG     = 0x88,
	OPCODE_MOV16_RM_REG    = 0x89,
	OPCODE_MOV8_REG_RM     = 0x8A,
	OPCODE_MOV16_REG_RM    = 0x8B,
	OPCODE_MOV16_RM_SEGREG = 0x8C,
	OPCODE_LEA16_RM         = 0x8D,
	OPCODE_MOV16_SEGREG_RM  = 0x8E,
	// ...
	OPCODE_MOV8_AL_MEM          = 0xA0,
	OPCODE_MOV16_AX_MEM         = 0xA1,
	OPCODE_MOV8_MEM_AL          = 0xA2,
	OPCODE_MOV16_MEM_AX         = 0xA3,
	// ...
	OPCODE_MOV8_AL_IMM          = 0xB0,
	OPCODE_MOV8_CL_IMM          = 0xB1,
	OPCODE_MOV8_DL_IMM          = 0xB2,
	OPCODE_MOV8_BL_IMM          = 0xB3,
	OPCODE_MOV8_AH_IMM          = 0xB4,
	OPCODE_MOV8_CH_IMM          = 0xB5,
	OPCODE_MOV8_DH_IMM          = 0xB6,
	OPCODE_MOV8_BH_IMM          = 0xB7,
	OPCODE_MOV16_AX_IMM         = 0xB8,
	OPCODE_MOV16_CX_IMM         = 0xB9,
	OPCODE_MOV16_DX_IMM         = 0xBA,
	OPCODE_MOV16_BX_IMM         = 0xBB,
	OPCODE_MOV16_SP_IMM         = 0xBC,
	OPCODE_MOV16_BP_IMM         = 0xBD,
	OPCODE_MOV16_SI_IMM         = 0xBE,
	OPCODE_MOV16_DI_IMM         = 0xBF,

	OPCODE_MOV8_MEM_IMM         = 0xC6,
	OPCODE_MOV16_MEM_IMM        = 0xC7,
};

typedef struct {
	enum InstructionOpcode opcode;
	uint8_t* data;
	ptrdiff_t len;

	int32_t sign_extend;
	int32_t direction;
	int32_t wide;           // 0 = 8-bit, 1 = 16-bit
	int32_t rm;             // Register/Memory field
	int32_t reg;            // Register field
	int32_t mod;            // Mode field

	int32_t direct_address;
	// int32_t disp;
	// int32_t imm;
	// int16_t direct_address;
	int16_t disp;
	int16_t imm;
} Instruction;

enum Register {
	Reg_AL,
	Reg_CL,
	Reg_DL,
	Reg_BL,
	Reg_AH,
	Reg_CH,
	Reg_DH,
	Reg_BH,

	Reg_AX,
	Reg_CX,
	Reg_DX,
	Reg_BX,
	Reg_SP,
	Reg_BP,
	Reg_SI,
	Reg_DI,
};

static char* register_names[] = {
	[Reg_AL] = "al",
	[Reg_CL] = "cl",
	[Reg_DL] = "dl",
	[Reg_BL] = "bl",
	[Reg_AH] = "ah",
	[Reg_CH] = "ch",
	[Reg_DH] = "dh",
	[Reg_BH] = "bh",
	[Reg_AX] = "ax",
	[Reg_CX] = "cx",
	[Reg_DX] = "dx",
	[Reg_BX] = "bx",
	[Reg_SP] = "sp",
	[Reg_BP] = "bp",
	[Reg_SI] = "si",
	[Reg_DI] = "di",
};


