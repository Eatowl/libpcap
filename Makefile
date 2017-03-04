CC=gcc
CLEAN=rm -f
PROGRAM_NAME=sniffer

$(PROGRAM_NAME): sniff_func.o main.o
	$(CC) -Wall -o $(PROGRAM_NAME) -g sniff_func.o main.o -O2 -lpcap
fm_func.o: sniff_func.c sniff_func.h
	$(CC) -Wall -c sniff_func.c -O2 -lpcap
main.o: main.c
	$(CC) -Wall -c main.c -O2 -lpcap
clean:
	$(CLEAN) *.o
	$(CLEAN) $(PROGRAM_NAME)