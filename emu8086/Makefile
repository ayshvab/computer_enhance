CC = clang-19
CFLAGS = -g -Wall -Wextra -Wconversion -Wdouble-promotion \
         -Wno-unused-parameter -Wno-unused-function -Wno-sign-conversion \
         -fsanitize=undefined -fsanitize-trap=undefined \
         -std=c23

DEBUG ?= 0
ifeq ($(DEBUG),1)
	CFLAGS += -DDEBUG
endif

SRC = emu8086.c

TARGET =emu8086

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all run clean
