# capstone library name (without prefix 'lib' and suffix '.so')
#CC = clang
CFLAGS = -Wall -O2 #-g
LIBNAME = capstone

diself: diself.o disassemble.o elf_64.o elf_32.o
	${CC} ${CFLAGS} $^ -O3 -Wall -l$(LIBNAME) -o $@

%.o: %.c
	${CC} ${CFLAGS} -c $^ -o $@

clean:
	rm *.o diself
