# capstone library name (without prefix 'lib' and suffix '.so')
CC = clang
LIBNAME = capstone

diself: diself.o disassemble.o
	${CC} $^ -O3 -Wall -l$(LIBNAME) -o $@

%.o: %.c
	${CC} -c $^ -o $@

clean:
	rm *.o diself
