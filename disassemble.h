#include <elf.h>
#include <stdlib.h>

size_t file_size(const char *fileName);

/* 64 bit functions */

void disasm_x86_64(Elf64_Ehdr *ehdr, uint32_t offset, size_t size, uint8_t *data);

void elf_disasm_64(Elf64_Ehdr *ehdr, Elf64_Shdr *shdr, char *str_table, uint8_t *data);


/* 32 bit functions */

void disasm_x86(Elf32_Ehdr *ehdr, uint32_t offset, size_t size, uint8_t *data);

void elf_disasm_32(Elf32_Ehdr *ehdr, Elf32_Shdr *shdr, char *str_table, uint8_t *data);
