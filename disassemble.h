#include <elf.h>
#include <stdlib.h>
#include <capstone/capstone.h>

size_t file_size(const char *fileName);

void disasm(uint64_t addr, uint32_t offset, size_t size, cs_arch arch, cs_mode mode, uint8_t *data);

void elf_disasm_x86_64(Elf64_Ehdr *ehdr, Elf64_Shdr *shdr, char *str_table, uint8_t *data);

void elf_disasm_x86(Elf32_Ehdr *ehdr, Elf32_Shdr *shdr, char *str_table, uint8_t *data);

void elf_disasm_arm64(Elf64_Ehdr *ehdr, Elf64_Shdr *shdr, char *str_table, uint8_t *data);

void elf_disasm_arm32(Elf32_Ehdr *ehdr, Elf32_Shdr *shdr, char *str_table, uint8_t *data);
