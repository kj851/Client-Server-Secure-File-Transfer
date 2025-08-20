CC        := gcc
CFLAGS    := -Wall -Wextra -O2 `pkg-config --cflags openssl`
LDFLAGS   := `pkg-config --libs openssl` -lcrypto -lssl -pthread

SRCS      := server.c client.c
TARGETS   := server client

.PHONY: all clean

all: $(TARGETS)

server: server.c
	$(CC) $(gcc) -o $@ $< $(LDFLAGS)

client: client.c
	$(CC) $(gcc) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGETS) *.o