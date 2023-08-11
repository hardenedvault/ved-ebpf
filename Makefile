OUTDIR = ./bin
TARGET = bpf_ed
OBJECTS = ./exploit_detect.o ./main.o ./objdump.o

CC = clang++
BCC_INC = /usr/include/bcc/
BCC_LIB = bcc

all: main clean_obj

objects: $(OBJECTS)

exploit_detect.o: ./exploit_detect/exploit_detect.cc ./exploit_detect/exploit_detect.h
	$(CC) -c ./exploit_detect/exploit_detect.cc -I$(BCC_INC)

objdump.o:
	$(CC) -c objdump.cc -I$(BCC_INC)

main.o: main.cc main.h
	$(CC) -c main.cc -I$(BCC_INC)

main: objects
	mkdir -p $(OUTDIR)
	$(CC) -o $(OUTDIR)/$(TARGET) $(OBJECTS) -l$(BCC_LIB)

clean:
	rm -rf $(OUTDIR)

clean_obj:
	rm ./*.o
