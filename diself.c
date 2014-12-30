#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "disassemble.h"
#include "elf_32.h"
#include "elf_64.h"


int main(int argc, char *argv[])
{
    if ( argc != 2 ) {
        printf("Usage: %s <file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    
    FILE *fd;
    char *fileName = argv[1];

    Elf64_Ehdr *ehdr = NULL; /* ELF header */
    Elf64_Shdr *shdr = NULL; /* Section header */

    Elf32_Ehdr *ehdr_32 = NULL;
    Elf32_Shdr *shdr_32 = NULL;
    
    char *str_table = NULL;

    if ((fd = fopen(fileName, "rb")) == NULL) {
        perror("Error");
        exit(EXIT_FAILURE);
    }

    uint8_t *data = mmap(NULL, file_size(fileName), PROT_READ, MAP_SHARED, fileno(fd), 0);

    ehdr = read_elf_header_64(fd);
    
    if (ehdr == NULL) {
        printf("%s: File format not recognized\n", fileName);
        exit(EXIT_FAILURE);
    }

    if (ehdr->e_ident[EI_CLASS] == ELFCLASS64) {
        shdr = read_section_header_64(ehdr, fd);
    
        if (shdr == NULL) {
            printf("Can't read section header\n");
            exit(EXIT_FAILURE);
        }

        str_table = load_string_table_64(ehdr, shdr, fd);
        
        if (str_table == NULL) {
            printf("Can't load string table\n");
            exit(EXIT_FAILURE);
        }

        if (ehdr->e_machine == EM_X86_64) {
            printf("ELF x86-64\n");
            elf_disasm_x86_64(ehdr,shdr,str_table, data);
            goto end_64;
        }
        if (ehdr->e_machine == EM_ARM) {
            printf("ELF ARM64\n");
            elf_disasm_arm64(ehdr,shdr,str_table, data);
            goto end_64;
        }
        else {
            printf("%s: Unsupported target architecture\n", fileName);
            goto end_64;
        }
    }

    if (ehdr->e_ident[EI_CLASS] == ELFCLASS32) {
        ehdr_32 = read_elf_header_32(fd);
        shdr_32 = read_section_header_32(ehdr_32, fd);
    
        if (shdr_32 == NULL) {
            printf("Can't read section header\n");
            exit(EXIT_FAILURE);
        }

        str_table = load_string_table_32(ehdr_32, shdr_32, fd);

        if (str_table == NULL) {
            printf("Can't load string table\n");
            exit(EXIT_FAILURE);
        }

        if (ehdr->e_machine == EM_386) {
            printf("ELF x86\n");
            elf_disasm_x86(ehdr_32, shdr_32, str_table, data);
            goto end_32;
        }
        if (ehdr->e_machine == EM_ARM) {
            printf("ELF ARM32\n");
            elf_disasm_arm32(ehdr_32, shdr_32, str_table, data);
            goto end_32;
        }
        else {
            printf("%s: Unsupported target architecture\n", fileName);
            goto end_32;
        }
    }

    else {
        printf("%s: Unsupported target architecture\n", fileName);
        goto end;
    }

end_64:
    free(ehdr);
    free(shdr);
    free(str_table);
    fclose(fd);
    return 0;
end_32:
    free(ehdr);
    free(ehdr_32);
    free(shdr_32);
    free(str_table);
    fclose(fd);
    return 0;
end:
    free(ehdr);
    fclose(fd);
    return 0;
}
