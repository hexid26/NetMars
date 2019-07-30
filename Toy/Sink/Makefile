CC=clang++
CFLAGS=-Wall -g -DSOLUTION -O3
PROGS=sink

all: $(PROGS)

sink:
	$(CC) $(CFLAGS) sink.cpp -o sink

clean:
	-rm -f *.o $(PROGS)
