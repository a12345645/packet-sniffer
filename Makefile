CC = gcc
OBJS = rxtest.o

all: rxtest

%.o: %.c
	$(CC) -c -o $@ $<

rxtest: $(OBJS)
	$(CC) -o $@ $^