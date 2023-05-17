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


int parse_signature(t_signtool *signtool, unsigned char *sign, size_t *signlen) {
	const char* section_name = ".signature";

    // ELF 파일을 메모리로 매핑
    void* file_data = mmap(NULL, signtool->exec_length, PROT_READ, MAP_PRIVATE, 
		fileno(signtool->exec_fp), 0);
    if (file_data == MAP_FAILED)
        error("mmap");

    // ELF 파일 헤더 확인
    Elf64_Ehdr* elf_header = (Elf64_Ehdr*)file_data;
    if (memcmp(elf_header->e_ident, ELFMAG, SELFMAG) != 0) {
        munmap(file_data, signtool->exec_length);
		error("Not an ELF file");
    }

    // 섹션 헤더 시작 주소 계산
    Elf64_Shdr* section_header_table = (Elf64_Shdr*)((char*)file_data + elf_header->e_shoff);

    // 섹션 이름 테이블 확인
    Elf64_Shdr* section_name_table = &section_header_table[elf_header->e_shstrndx];
    char* section_names = (char*)file_data + section_name_table->sh_offset;

    // 섹션 반복하여 특정 섹션 찾기
    for (int i = 0; i < elf_header->e_shnum; i++) {
        char* name = &section_names[section_header_table[i].sh_name];
        if (strcmp(name, section_name) == 0) {
            // 특정 섹션 찾음
            void* section_data = (unsigned char*)file_data + section_header_table[i].sh_offset;
            *signlen = section_header_table[i].sh_size;

            // 섹션 내용 출력 또는 원하는 작업 수행
			if (sign != NULL) {
				for (size_t j = 0; j < *signlen; j++) {
					sign[j] = ((unsigned char*)section_data)[j];
				}
			}
			return (1);
        }
    }

    munmap(file_data, signtool->exec_length);
	return (0);
}
