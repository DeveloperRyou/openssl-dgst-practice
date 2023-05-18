#include "signtool.h"

void parse_operator(t_signtool *signtool, char **operator)
{
	if (strcmp(operator[1], "sign") == 0)
		signtool->operator = SIGN;
	else if (strcmp(operator[1], "verify") == 0)
		signtool->operator = VERIFY;
	else
		error("Invalid operator");

	for (int i = 2; i < 6; i+=2)
	{
		if (strcmp(operator[i], "-k") == 0)
			signtool->key_filename = operator[i + 1];
		else if (strcmp(operator[i], "-e") == 0)
			signtool->exec_filename = operator[i + 1];
		else
			error("Invalid argument");
	}
}

int parse_excutable_section(FILE *elf_fp, unsigned char **text, size_t *textlen) {
	*textlen = 0;
	// get length
	fseek(elf_fp, 0, SEEK_END);
	size_t execlen = ftell(elf_fp);
	rewind(elf_fp);

	// elf to memory
    void* file_data = mmap(NULL, execlen, PROT_READ, MAP_PRIVATE, 
		fileno(elf_fp), 0);
    if (file_data == MAP_FAILED)
        error("mmap");

    // get elf header
    Elf64_Ehdr* elf_header = (Elf64_Ehdr*)file_data;
    if (memcmp(elf_header->e_ident, ELFMAG, SELFMAG) != 0) {
        munmap(file_data, execlen);
		error("Not an ELF file");
    }

    // calculate section header table
    Elf64_Shdr* header_table = (Elf64_Shdr*)((char*)file_data + elf_header->e_shoff);

    // find section
    for (int i = 0; i < elf_header->e_shnum; i++)
        if (header_table[i].sh_flags & SHF_EXECINSTR)
            *textlen += header_table[i].sh_size;
	if (*textlen == 0)
		return (0);

	// get section
	*text = (unsigned char *)malloc(*textlen);
	if (*text == NULL)
		error("section malloc error");
	bzero(*text, *textlen);
	size_t index = 0;
    for (int i = 0; i < elf_header->e_shnum; i++) {
        if (header_table[i].sh_flags & SHF_EXECINSTR) {
            void* section_data = (unsigned char*)file_data + header_table[i].sh_offset;
			size_t sectionlen = header_table[i].sh_size;

			for (size_t j = 0; j < sectionlen; j++) {
				(*text)[index + j] = ((unsigned char*)section_data)[j];
			}
			index += sectionlen;
        }
    }

    munmap(file_data, execlen);
	return (1);
}


int parse_section(FILE *elf_fp, const char *section, 
	unsigned char **text, size_t *textlen) {
	*textlen = 0;
	
	// get length
	fseek(elf_fp, 0, SEEK_END);
	size_t execlen = ftell(elf_fp);
	rewind(elf_fp);

	// elf to memory
    void* file_data = mmap(NULL, execlen, PROT_READ, MAP_PRIVATE, 
		fileno(elf_fp), 0);
    if (file_data == MAP_FAILED)
        error("mmap");

    // get elf header
    Elf64_Ehdr* elf_header = (Elf64_Ehdr*)file_data;
    if (memcmp(elf_header->e_ident, ELFMAG, SELFMAG) != 0) {
        munmap(file_data, execlen);
		error("Not an ELF file");
    }

    // calculate section header table
    Elf64_Shdr* header_table = (Elf64_Shdr*)((char*)file_data + elf_header->e_shoff);

    // make section table
    Elf64_Shdr* table = &header_table[elf_header->e_shstrndx];
    char* sections = (char*)file_data + table->sh_offset;

	int flag = 0;
    // find section
    for (int i = 0; i < elf_header->e_shnum; i++) {
        char* name = &sections[header_table[i].sh_name];
        if (strcmp(name, section) == 0) {
            void* section_data = (unsigned char*)file_data + header_table[i].sh_offset;
            *textlen = header_table[i].sh_size;
			
            // get section
			*text = (unsigned char *)malloc(*textlen);
			if (*text == NULL)
				error("section malloc error");
			bzero(*text, *textlen);
			for (size_t j = 0; j < *textlen; j++) {
				(*text)[j] = ((unsigned char*)section_data)[j];
			}
			flag = 1;
			break;
        }
    }

    munmap(file_data, execlen);
	return (flag);
}
