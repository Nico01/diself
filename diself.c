#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <sys/mman.h>

#include "disassemble.h"

int main(int argc, char *argv[])
{
    if ( argc != 2 ) {
        printf("Usage: %s <file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    
    FILE *fd;
    
    char *fileName = argv[1];

    uint8_t *data;

    Elf64_Ehdr *ehdr = NULL; /* ELF header */
    Elf64_Shdr *shdr = NULL; /* Section header */

    Elf32_Ehdr *ehdr_32 = NULL;
    Elf32_Shdr *shdr_32 = NULL;
    
    char *str_table = NULL;

    if ((fd = fopen(fileName, "rb")) == NULL) {
        perror("Error");
        exit(EXIT_FAILURE);
    }

    data = mmap(NULL, file_size(fileName), PROT_READ, MAP_SHARED, fileno(fd), 0);

    ehdr = read_elf_header(fd);
    
    if (ehdr == NULL) {
        printf("%s: File format not recognized\n", fileName);
        exit(EXIT_FAILURE);
    }

    if (ehdr->e_ident[EI_CLASS] == ELFCLASS64 && ehdr->e_machine == EM_X86_64) {
        shdr = read_section_header(ehdr, fd);
    
        if (shdr == NULL) {
            printf("Can't read section header\n");
            exit(EXIT_FAILURE);
        }

        str_table = load_string_table(ehdr, shdr, fd);

        elf_disasm(ehdr,shdr,str_table, data);
    
        free(ehdr);
        free(shdr);
        free(str_table);
        fclose(fd);
        return 0;
    }
    if (ehdr->e_ident[EI_CLASS] == ELFCLASS32 && ehdr->e_machine == EM_386) {
        ehdr_32 = read_elf_header_32(fd);
        shdr_32 = read_section_header_32(ehdr_32, fd);
    
        if (shdr_32 == NULL) {
            printf("Can't read section header\n");
            exit(EXIT_FAILURE);
        }

        str_table = load_string_table_32(ehdr_32, shdr_32, fd);

        elf_disasm_32(ehdr_32,shdr_32,str_table, data);

        free(ehdr);
        free(ehdr_32);
        free(shdr_32);
        free(str_table);
        fclose(fd);
        return 0;
    }     
    else {
        printf("%s: Unsupported target architecture\n", fileName);
        free(ehdr);
        fclose(fd);
        return 0;
    }
}
