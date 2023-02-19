all: bin/otpdump

clean:
	rm -rf bin

bin/otpdump: otpdump.c |bin
	$(CC) -o $@ $<

bin:
	mkdir -p bin
