#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

enum Status_Code { 
	status_code_ok = 0,
	status_code_failure = 1,
};

static int g_status_code = EXIT_SUCCESS;

#define HANDLE_ERROR(msg) \
	do { perror(msg); exit(EXIT_FAILURE); } while(0)


enum Status_Code
decode_instructions(char *machine_code, ssize_t size);

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

	char *machine_code = mmap(NULL, file_stat.st_size, PROT_READ,
		MAP_PRIVATE, machine_code_fd, 0);

	enum Status_Code rc = decode_instructions(machine_code, file_stat.st_size);
	if (rc != status_code_ok)
	{
		fprintf(stderr, "Fail to decode\n");
		g_status_code = rc;
	}

	munmap(machine_code, file_stat.st_size);
	close(machine_code_fd);

	exit(g_status_code);
}

enum Status_Code
decode_instructions(char *machine_code, ssize_t size)
{
	return 0;
}