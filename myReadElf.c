#include "myReadElf.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

static void readElfHeader(char *);
static void readElfSecHeader(char *);
static void readShStrTable(char *);
static void readStrTable(char *);
static void showMenu();

int main(int argc, char *argv[], char *envp[]) {

	/* It should judge the file type here */
	if(argc <= 2) {
		printf("too few arguments!\n");
		showMenu();
		exit(0);
	}
	if(!strcmp(argv[1], "--help")) {
		showMenu();
	} else if(!strcmp(argv[1], "-h")) {
		readElfHeader(argv[2]);
	} else if(!strcmp(argv[1], "-s")) {
		readElfSecHeader(argv[2]);
	} else if(!strcmp(argv[1], "-sstr")) {
		readShStrTable(argv[2]);
	} else if(!strcmp(argv[1], "-str")) {
		readStrTable(argv[2]);
	} else {
		showMenu();
	}
	return 0;
}

void showMenu() {
	printf("This is my readelf program, you can choose the following choices\n");
	printf("\t--help\t\t\tshow the menu\n");
	printf("\t-h\t\t\tshow the elf file header\n");
	printf("\t-s\t\t\tshow the elf file sections\n");
	printf("\t-str\t\t\tshow the elf file string table\n");
	printf("\t-sstr\t\t\tshow the elf file section string table\n");
}

void readElfHeader(char *file) {
	printf("reading elf file header now!\n");

	int fp,fsize,i;
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
	// printf("elf file header identity: %s\n", buf->e_ident);
	
	/* showing the identity of the elf file */
	identity = buf->e_ident;
	printf("elf file magic number: ");
	for(i = 0; i < 4; i++) {
		printf("%x ", identity[i]);
	}
	printf("\n");

	if(identity[4] == 0x01) 
		printf("elf file class: It is an ELF32 file\n");
	else if(identity[4] == 0x02) 
		printf("elf file class: It is an ELF64 file\n");
	else {
		printf("wrong file type!");
		exit(0);
	}

	if(identity[5] == 0x01)
		printf("elf file data: The file is in small endian\n");
	else if(identity[5] == 0x02)
		printf("elf file data: The file is in large endian\n");
	else {
		printf("wrong file type!");
		exit(0);
	}

	printf("elf file version: %d\n", identity[6]);

	/* showing the remaining part of the file */
	// printf("elf file type: %d\n", buf->e_type);
	
	if(buf->e_type == 0x01) 
		printf("elf file type: relocated file\n");
	else if(buf->e_type == 0x02)
		printf("elf file type: execution file\n");
	else if(buf->e_type == 0x03)
		printf("elf file type: dynamic share file\n");

	printf("elf file machine: %hu\n", buf->e_machine);
	printf("elf file version: %lu\n", buf->e_version);
	printf("elf file entry point: %llu\n", buf->e_entry);
	printf("elf file program header table offset: %lld bytes\n", buf->e_phoff);
	printf("elf file section header table offset: %lld bytes\n", buf->e_shoff);
	printf("elf file flags: %lu\n", buf->e_flags);
	printf("elf file header size: %hu\n", buf->e_ehsize);
	printf("elf file program header table entry size: %hu bytes\n", buf->e_phentsize);
	printf("elf file program header table entry count: %hu\n", buf->e_phnum);
	printf("elf file section header table entry size: %hu bytes\n", buf->e_shentsize);
	printf("elf file section header table entry count: %hu\n", buf->e_shnum);
	printf("elf file section header string table index: %hu\n", buf->e_shstrndx);

	free(buf);
	close(fp);
	buf = NULL;
}

void readElfSecHeader(char *filename) {
	printf("reading elf file section headers!\n");

	int fp, fsize, fseek, i;
	Elf64_Ehdr *buf;
	int secHeadOff, secEntSize, secNum;
	Elf64_Shdr *sectionHeaders, *tmpSecHead;
	fp = open(filename, O_RDONLY);
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
	
	secHeadOff = buf->e_shoff;
	secEntSize = buf->e_shentsize;
	secNum = buf->e_shnum;	
	fseek = lseek(fp, secHeadOff, SEEK_SET);
	if(fseek < 0) {
		printf("fail to read elf file!\n");
		exit(0);
	}
	
	sectionHeaders = (Elf64_Shdr*)malloc(sizeof(Elf64_Shdr)*secNum);
	if(!sectionHeaders) {
		printf("no enough memory in the heap!\n");
		exit(0);
	}
	tmpSecHead = sectionHeaders;

	fsize = read(fp, tmpSecHead, sizeof(Elf64_Shdr)*secNum);
	if(fsize <= 0) {
		printf("fail to read file, please check it");
		exit(0);
	}

	printf("section headers:\n");
	printf("Index\t Name\t Type\t Flag\t Addr\t\t Offset\t Size\t Link\t Info\t AddrAlign\t EntSize\n");
	for(i = 0; i < secNum; i++) {
		printf("%d\t %lu\t %lu\t %llu\t %llu\t %llu\t %llu\t %lu\t %lu\t %llu\t %llu\n",
				i, (Elf64_Shdr*)tmpSecHead->sh_name, (Elf64_Shdr*)tmpSecHead->sh_type, 
				(Elf64_Shdr*)tmpSecHead->sh_flags, (Elf64_Shdr*)tmpSecHead->sh_addr, 
				(Elf64_Shdr*)tmpSecHead->sh_offset, (Elf64_Shdr*)tmpSecHead->sh_size,
				(Elf64_Shdr*)tmpSecHead->sh_link, (Elf64_Shdr*)tmpSecHead->sh_info, 
				(Elf64_Shdr*)tmpSecHead->sh_addralign, (Elf64_Shdr*)tmpSecHead->sh_entsize);
		tmpSecHead++;
	}

	close(fp);
	free(buf);
	free(sectionHeaders);
	buf == NULL;
	sectionHeaders = NULL;
}

void readShStrTable(char *filename) {
	printf("reading elf file section string table\n");
	printf("Offset\t\tString\n");
	
	int fp, fsize, fseek, i, j;
	Elf64_Ehdr *buf;
	int secHeadOff, secEntSize, secNum, shStrTable, shStrTableOff, shStrTableSize;
	Elf64_Shdr *sectionHeaders, *tmpSecHead;
	unsigned char* shStrTableStr;
	fp = open(filename, O_RDONLY);
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

	shStrTable = buf->e_shstrndx;
	secHeadOff = buf->e_shoff;
	secEntSize = buf->e_shentsize;
	secNum = buf->e_shnum;
	fseek = lseek(fp, secHeadOff, SEEK_SET);
	if(fseek < 0) {
		printf("fail to read elf file!\n");
		exit(0);
	}
	
	sectionHeaders = (Elf64_Shdr*)malloc(sizeof(Elf64_Shdr)*secNum);
	if(!sectionHeaders) {
		printf("no enough memory in the heap!\n");
		exit(0);
	}
	tmpSecHead = sectionHeaders;

	fsize = read(fp, tmpSecHead, sizeof(Elf64_Shdr)*secNum);
	if(fsize <= 0) {
		printf("fail to read file, please check it");
		exit(0);
	}
	
	tmpSecHead += shStrTable;
	shStrTableOff = tmpSecHead->sh_offset;
	shStrTableSize = tmpSecHead->sh_size;

	fseek = lseek(fp, shStrTableOff, SEEK_SET);
       	if(fseek < 0) {
		printf("fail to read elf file!\n");
		exit(0);
	}
	
	shStrTableStr = malloc(shStrTableSize);
	fsize = read(fp, shStrTableStr, shStrTableSize);
	if(fsize <= 0) {
		printf("fail to read file, please check it");
		exit(0);
	}

	i = j = 0;
	while(i < shStrTableSize) {
		if(!shStrTableStr[i]) {
			printf("%d\t\t%s\n", j, shStrTableStr + j);
			j = i + 1;
		}
		i++;
	}

	close(fp);
        free(buf);
        free(sectionHeaders);
	free(shStrTableStr);
        buf == NULL;
        sectionHeaders = NULL;
	shStrTableStr = NULL;
}

void readStrTable(char *filename) {
        printf("reading elf file string table\n");
        printf("Offset\t\tString\n");

        int fp, fsize, fseek, i, j;
        Elf64_Ehdr *buf;
        int secHeadOff, secEntSize, secNum, shStrTable, shStrTableOff, shStrTableSize;
        Elf64_Shdr *sectionHeaders, *tmpSecHead;
        unsigned char* shStrTableStr;
        fp = open(filename, O_RDONLY);
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

        shStrTable = buf->e_shstrndx;
        secHeadOff = buf->e_shoff;
        secEntSize = buf->e_shentsize;
        secNum = buf->e_shnum;
        fseek = lseek(fp, secHeadOff, SEEK_SET);
        if(fseek < 0) {
                printf("fail to read elf file!\n");
                exit(0);
        }

        sectionHeaders = (Elf64_Shdr*)malloc(sizeof(Elf64_Shdr)*secNum);
        if(!sectionHeaders) {
                printf("no enough memory in the heap!\n");
                exit(0);
        }
        tmpSecHead = sectionHeaders;

        fsize = read(fp, tmpSecHead, sizeof(Elf64_Shdr)*secNum);
        if(fsize <= 0) {
                printf("fail to read file, please check it");
                exit(0);
        }

        tmpSecHead += shStrTable - 1;
        shStrTableOff = tmpSecHead->sh_offset;
        shStrTableSize = tmpSecHead->sh_size;

        fseek = lseek(fp, shStrTableOff, SEEK_SET);
        if(fseek < 0) {
                printf("fail to read elf file!\n");
                exit(0);
        }

        shStrTableStr = malloc(shStrTableSize);
        fsize = read(fp, shStrTableStr, shStrTableSize);
        if(fsize <= 0) {
                printf("fail to read file, please check it");
                exit(0);
        }

        i = j = 0;
        while(i < shStrTableSize) {
                if(!shStrTableStr[i]) {
                        printf("%d\t\t%s\n", j, shStrTableStr + j);
                        j = i + 1;
                }
                i++;
        }

        close(fp);
        free(buf);
        free(sectionHeaders);
        free(shStrTableStr);
        buf == NULL;
        sectionHeaders = NULL;
        shStrTableStr = NULL;
}
