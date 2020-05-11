#include "myReadElf.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

static void readElfHeader(char *);

int main(int argc, char *argv[], char *envp[]) {
	if(argc <= 2) {
		printf("too few arguments!");
		exit(0);
	}
	if(!strcmp(argv[1], "-h")) {
		readElfHeader(argv[2]);
	} else {
		printf("nothing happened!");
	}
	return 0;
}

void readElfHeader(char *file) {
	printf("reading elf file header now!\n");

	int fp,fsize;
	Elf64_Ehdr *buf = NULL;
	char *identity = NULL;
	Elf64_Half type, machine, ehsize, phentsize, phnum, shensize, shnum, shstrndx;
	Elf64_Word version, flags;
	Elf64_Addr entry;
	Elf64_Off shoff, phoff;

	fp = open(file, O_RDONLY);
	if(fp < 0) {
		printf("fail to open the file, please check the existence!\n");
		exit(0);
	}

	buf = (Elf64_Ehdr*)malloc(sizeof(Elf64_Ehdr));
	if(!buf) {
		printf("no enough memory in the heap!\n");
		exit(0);
	}	

	fsize = read(fp, buf, sizeof(Elf64_Ehdr));
	if(fsize <= 0) {
		printf("fail to read file, please check it");
		exit(0);
	}

	printf("showing elf file header:\n");
	printf("elf file header identity: %s\n", buf->e_ident);
	printf("elf file type: %d\n", buf->e_type);
	printf("elf file machine: %d\n", buf->e_machine);
	printf("elf file version: %u\n", buf->e_version);
	printf("elf file entry point: %lu\n", buf->e_entry);
	printf("elf file program header table offset: %ld bytes\n", buf->e_phoff);
	printf("elf file section header table offset: %ld bytes\n", buf->e_shoff);
	printf("elf file flags: %u\n", buf->e_flags);
	printf("elf file header size: %d\n", buf->e_ehsize);
	printf("elf file program header table entry size: %d bytes\n", buf->e_phentsize);
	printf("elf file program header table entry count: %d\n", buf->e_phnum);
	printf("elf file section header table entry size: %d bytes\n", buf->e_shentsize);
	printf("elf file section header table entry count: %d\n", buf->e_shnum);
	printf("elf file section header string table index: %d\n", buf->e_shstrndx);

	free(buf);
	buf = NULL;
}
