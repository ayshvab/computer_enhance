CFLAGS = -g -Wall -pedantic

%.o: %.c %.h
	$(CC) $(CFLAGS) -c $< -o $@

emu8086: emu8086.c
	$(CC) $(CFLAGS) $^ -o $@

clean:
	rm -f *.o emu8086