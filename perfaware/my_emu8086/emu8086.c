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
	uint16_t address;

	uint16_t data;
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

ssize_t
read_u16(uint16_t *destination, uint8_t *source)
{
	// *destination = ((uint16_t)source[1] << 8) | source[0];
	*destination = *(uint16_t *)source;
	return 2;
}

void instruction_read_data(struct Instruction *instruction, 
						   uint8_t *bytes, ssize_t *offset)
{
	if (instruction->wide)
	{
		*offset += read_u16(&instruction->data, &bytes[*offset]);
	}
	else
	{
		instruction->data = bytes[*offset];
		*offset += 1;
	}
}

void instruction_read_displacement16(struct Instruction *instruction, 
									 uint8_t *bytes, ssize_t *offset)
{
	*offset += read_u16(&instruction->displacement, &bytes[*offset]);
}


void instruction_read_displacement8(struct Instruction *instruction, 
									uint8_t *bytes, ssize_t *offset)
{
	instruction->displacement = bytes[*offset];
	*offset += 1;
}

void instruction_read_address(struct Instruction *instruction, 
									uint8_t *bytes, ssize_t *offset)
{
	*offset += read_u16(&instruction->address, &bytes[*offset]);
}

bool
is_register_or_memory_to_or_from_register(uint8_t byte)
{
	return 0x88 == (byte & 0xFC);
}

bool
is_immediate_to_register_or_memory(uint8_t byte)
{
	return 0xC6 == (byte & 0xFE);
}

bool
is_immediate_to_register(uint8_t byte)
{
	return 0xB0 == (byte & 0xF0);
}

bool
is_memory_to_acc_or_acc_to_memory(uint8_t byte)
{
	return 0xA0 == (byte & 0xF0);
}



enum Status_Code
decode_instruction(struct Byte_Stream *stream, struct Instruction *instruction)
{
	uint8_t *bytes = stream->base+stream->offset;
	ssize_t offset = 0;

	instruction->bytes[0] = bytes[0];

	if (is_register_or_memory_to_or_from_register(bytes[offset]))
	{
		instruction->direction = (bytes[offset] & 2) >> 1;
		instruction->wide = (bytes[offset] & 1);
		offset += 1;

		instruction->mod = (bytes[offset] >> 6) & 0x03;
		instruction->reg = (bytes[offset] >> 3) & 0x07;
		instruction->reg_or_mem = bytes[offset] & 0x07;
		offset += 1;

		if (instruction->mod == 0)
		{
			if (instruction->reg_or_mem == 0x06)
				instruction_read_displacement16(instruction, bytes, &offset);
		}
		else if (instruction->mod == 1)
			instruction_read_displacement8(instruction, bytes, &offset);
		else if (instruction->mod == 2)
			instruction_read_displacement16(instruction, bytes, &offset);
	}
	else if (is_immediate_to_register_or_memory(bytes[offset]))
	{
		instruction->direction = 1;
		instruction->wide = (bytes[offset] & 1);
		offset += 1;

		instruction->mod = (bytes[offset] >> 6) & 0x03;
		instruction->reg_or_mem = bytes[offset] & 0x07;
		offset += 1;

		if (instruction->mod == 0)
		{
			if (instruction->reg_or_mem == 0x06)
			{
				instruction_read_displacement16(instruction, bytes, &offset);
				instruction_read_data(instruction, bytes, &offset);
			}
			else
				instruction_read_data(instruction, bytes, &offset);
		}
		else if (instruction->mod == 1)
		{
			instruction_read_displacement8(instruction, bytes, &offset);
			instruction_read_data(instruction, bytes, &offset);
		}
		else if (instruction->mod == 2)
		{
			instruction_read_displacement16(instruction, bytes, &offset);
			instruction_read_data(instruction, bytes, &offset);
		}
	}
	else if (is_immediate_to_register(bytes[offset]))
	{
		instruction->wide = (bytes[offset] >> 3) & 1;
		instruction->reg = bytes[offset] & 0x07;
		offset += 1;
		instruction_read_data(instruction, bytes, &offset);
	}
	else if (is_memory_to_acc_or_acc_to_memory(bytes[offset]))
	{
		instruction->wide = bytes[offset] & 1;
		instruction->direction = (bytes[offset] & 2) >> 1;
		offset += 1;
		instruction_read_address(instruction, bytes, &offset);
	}
	else
		return status_code_failure;
	
	stream->offset += offset;
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
				fprintf(stdout, "mov [%s%+d], %s\n", effective_address, (int16_t)displacement, reg );
		}
	}
	else if (is_immediate_to_register_or_memory(instruction->bytes[0]))
	{
		if (instruction->mod == 0)
		{
			// special case: DIRECT ADDRESS
			if (instruction->reg_or_mem == 0x06)
			{
				if (instruction->wide)
					fprintf(stdout, "mov [%d], word %+d\n", instruction->displacement, instruction->data);
				else
					fprintf(stdout, "mov [%d], byte %+d\n", instruction->displacement, (int8_t)instruction->data);
			}
			else 
			{
				char *effective_address = effective_address_table[instruction->reg_or_mem];	

				if (instruction->wide)
					fprintf(stdout, "mov [%s], word %+d\n", effective_address, instruction->data);
				else
					fprintf(stdout, "mov [%s], byte %+d\n", effective_address, (int8_t)instruction->data);
			}
		}
		else if (instruction->mod == 1)
		{
			char *effective_address = effective_address_table[instruction->reg_or_mem];	
			uint16_t displacement = instruction->displacement;
			if (instruction->wide)
				fprintf(stdout, "mov [%s%+d], word %+d\n", effective_address, (int8_t)displacement, instruction->data);
			else
				fprintf(stdout, "mov [%s%+d], byte %+d\n", effective_address, (int8_t)displacement, (int8_t)instruction->data);
		}
		else if (instruction->mod == 2)
		{
			char *effective_address = effective_address_table[instruction->reg_or_mem];	
			uint16_t displacement = instruction->displacement;
			if (instruction->wide)
				fprintf(stdout, "mov [%s%+d], word %+d\n", effective_address, displacement, instruction->data);
			else
				fprintf(stdout, "mov [%s%+d], byte %+d\n", effective_address, displacement, (int8_t)instruction->data);
		}
	}
	else if (is_immediate_to_register(instruction->bytes[0]))
	{
		char *reg = register_table[instruction->reg + 8*instruction->wide];
		if (instruction->wide)
			fprintf(stdout, "mov %s, word %+d\n", reg, instruction->data);
		else
			fprintf(stdout, "mov %s, byte %+d\n", reg, (int8_t)instruction->data);
	}
	else if (is_memory_to_acc_or_acc_to_memory(instruction->bytes[0]))
	{
		char *reg = register_table[0 + 8*instruction->wide];
		if (instruction->direction)
			fprintf(stdout, "mov [%d], %s\n", instruction->address, reg);
		else
			fprintf(stdout, "mov %s, [%d]\n", reg, instruction->address);
	}
	else
	{
		fprintf(stdout, "Fail to print instruction: %x\n", instruction->bytes[0]);
	}
}


