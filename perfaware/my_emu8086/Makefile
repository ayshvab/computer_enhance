CC=gcc
CFLAGS = -g -Wall -pedantic -std=c99

PROG=emu8086
SOURCES=emu8086.c
	
%.o: %.c %.h
	$(CC) $(CFLAGS) -c $< -o $@

$(PROG): $(SOURCES)
	$(CC) $(CFLAGS) $^ -o $@

test: $(PROG)
	python3 ./test.py

clean:
	rm -f *.o emu8086
	rm -r ./test-tmp
