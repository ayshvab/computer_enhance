#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>

//////////////////////////////////////////////////////////////////////

enum Status_Code { 
	status_code_ok = 0,
	status_code_failure = 1,
};


#define HANDLE_ERROR(msg) \
	do { perror(msg); exit(EXIT_FAILURE); } while(0)

struct Instruction
{
	uint8_t bytes[6];

	uint8_t direction;
	uint8_t wide;

	uint8_t mod;
	uint8_t reg;
	uint8_t reg_or_mem;

	uint16_t displacement;

	uint8_t addr_lo;
	uint8_t addr_hi;

	uint8_t data_lo;
	uint8_t data_hi;
};

struct Byte_Stream
{
	uint8_t *base;
	ssize_t size;
	ssize_t offset;
};

//////////////////////////////////////////////////////////////////////

enum Status_Code 
decode_instruction(struct Byte_Stream *, struct Instruction *);

void 
print_instruction(struct Instruction *);

//////////////////////////////////////////////////////////////////////

static int g_status_code = EXIT_SUCCESS;

static char register_table[][3] = {
	"al", "cl", "dl", "bl", "ah", "ch", "dh", "bh", 
	"ax", "cx", "dx", "bx", "sp", "bp", "si", "di",
};

static char effective_address_table[][6] = {
	"bx+si", "bx+di", "bp+si", "bp+di", "si", "di", "bp", "bx"
};

//////////////////////////////////////////////////////////////////////

int main(int argc, char **argv)
{
	if (argc != 2)
	{
		fprintf(stderr, "Usage: emu8086 ./8086_machine_code\n");
		exit(EXIT_FAILURE);
	}

	int machine_code_fd = open(argv[1], O_RDONLY);
	if (machine_code_fd == -1)
		HANDLE_ERROR("open");

	struct stat file_stat;
	if (fstat(machine_code_fd, &file_stat) == -1)
		HANDLE_ERROR("fstat");

	uint8_t *machine_code = mmap(NULL, file_stat.st_size, PROT_READ,
		MAP_PRIVATE, machine_code_fd, 0);

	struct Byte_Stream instruction_stream = {
		.base = machine_code,
		.size = file_stat.st_size,
	};

	struct Instruction instruction = {0};

	if (instruction_stream.offset < instruction_stream.size)
		fprintf(stdout, "bits 16\n");

	enum Status_Code rc;
	while(instruction_stream.offset < instruction_stream.size)
	{
		rc = decode_instruction(&instruction_stream, &instruction);
		if (rc != status_code_ok)
		{
			fprintf(stderr, "Fail to decode. instruction.bytes[0] = %x\n", instruction.bytes[0]);
			g_status_code = rc;
			break;
		}

		print_instruction(&instruction);
	}
	
	munmap(machine_code, file_stat.st_size);
	close(machine_code_fd);

	exit(g_status_code);
}

//////////////////////////////////////////////////////////////////////

void
read_u16(uint16_t *destination, uint8_t *source)
{
	// *destination = ((uint16_t)source[1] << 8) | source[0];
	*destination = *(uint16_t *)source;
}

bool
is_register_or_memory_to_or_from_register(uint8_t byte)
{
	return 0x88 == (byte & 0xFC);
}

enum Status_Code
decode_instruction(struct Byte_Stream *stream, struct Instruction *instruction)
{
	uint8_t *bytes = stream->base+stream->offset;
	ssize_t step = 0;

	instruction->bytes[0] = bytes[0];

	if (is_register_or_memory_to_or_from_register(bytes[0]))
	{
		instruction->direction = (bytes[0] & 2) >> 1;
		instruction->wide = (bytes[0] & 1);
		step += 1;

		instruction->mod = (bytes[1] >> 6) & 0x03;
		instruction->reg = (bytes[1] >> 3) & 0x07;
		instruction->reg_or_mem = bytes[1] & 0x07;
		step += 1;

		if (instruction->mod == 0)
		{
			if (instruction->reg_or_mem == 0x06)
			{
				read_u16(&instruction->displacement, &bytes[2]);
				step += 2;
			}
		}
		else if (instruction->mod == 1)
		{
			instruction->displacement = bytes[2];
			step += 1;
		}
		else if (instruction->mod == 2)
		{
			read_u16(&instruction->displacement, &bytes[2]);
			step += 2;
		}
	}
	else
		return status_code_failure;
	
	stream->offset += step;
	return status_code_ok;
}


void
print_instruction(struct Instruction *instruction)
{
	if (is_register_or_memory_to_or_from_register(instruction->bytes[0]))
	{
		if (instruction->mod == 3)
		{
			char *reg1 = register_table[instruction->reg + 8*instruction->wide];
			char *reg2 = register_table[instruction->reg_or_mem + 8*instruction->wide];

			if (instruction->direction) 
				fprintf(stdout, "mov %s, %s\n", reg1, reg2);
			else
				fprintf(stdout, "mov %s, %s\n", reg2, reg1);
		}
		else if (instruction->mod == 0)
		{
			char *reg = register_table[instruction->reg + 8*instruction->wide];
			// special case: DIRECT ADDRESS
			if (instruction->reg_or_mem == 0x06)
			{
				if (instruction->direction)
					fprintf(stdout, "mov %s, [%d]\n", reg, instruction->displacement);
				else
					fprintf(stdout, "mov [%d], %s\n", instruction->displacement, reg);
			}
			else 
			{
				char *effective_address = effective_address_table[instruction->reg_or_mem];	
				if (instruction->direction)
					fprintf(stdout, "mov %s, [%s]\n", reg, effective_address);
				else
					fprintf(stdout, "mov [%s], %s\n", effective_address, reg);
			}
		}
		else if (instruction->mod == 1)
		{
			char *reg = register_table[instruction->reg + 8*instruction->wide];
			char *effective_address = effective_address_table[instruction->reg_or_mem];	
			uint16_t displacement = instruction->displacement;
			if (instruction->direction)
				fprintf(stdout, "mov %s, [%s%+d]\n", reg, effective_address, (int8_t)displacement);
			else
				fprintf(stdout, "mov [%s%+d], %s\n", effective_address, (int8_t)displacement, reg );
		}
		else if (instruction->mod == 2)
		{
			char *reg = register_table[instruction->reg + 8*instruction->wide];
			char *effective_address = effective_address_table[instruction->reg_or_mem];	
			uint16_t displacement = instruction->displacement;
			if (instruction->direction)
				fprintf(stdout, "mov %s, [%s%+d]\n", reg, effective_address, displacement);
			else
				fprintf(stdout, "mov [%s%+d], %s\n", effective_address, displacement, reg );
		}
	}
	else
	{
		fprintf(stdout, "Fail to print instruction: %x\n", instruction->bytes[0]);
	}
}


/*
void
print_instruction(struct Instruction *instruction)
{
	// fprintf(stdout, "%x\n", instruction->bytes[0]);
	switch (instruction->bytes[0])
	{
	// Register/memory to/from register
	case 0x88:
	case 0x89:
	case 0x8A:
	case 0x8B:
	{
		if (instruction->mod == 3)
		{
			char *reg1 = register_table[instruction->reg + 8*instruction->wide];
			char *reg2 = register_table[instruction->reg_or_mem + 8*instruction->wide];

			char *source;
			char *destination;

			if (instruction->direction)
			{
				source = reg2;
				destination = reg1;
			}
			else
			{
				source = reg1;
				destination = reg2;
			}
			fprintf(stdout, "mov %s, %s\n", destination, source);
		}
	} break;

	default:
		fprintf(stdout, "Fail to print instruction: %x\n", instruction->bytes[0]);
	}
}
*/

