
CC ?= gcc
LD ?= ld

CURRENT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
BUILDDIR := $(CURRENT_DIR)build
CLIENT = $(CURRENT_DIR)build/tls-client
SERVER = $(CURRENT_DIR)build/tls-server

CLIENT_SRC := $(CURRENT_DIR)src/client.c
SERVER_SRC := $(CURRENT_DIR)src/server.c

LIB := -ldl -lcrypto -lssl

.PHONY: all
all: $(CLIENT) $(SERVER)


$(CLIENT): $(BUILDDIR)
	@echo "   Build mode : Building target $@ ..."
	$(CC) $(CLIENT_SRC) $(CFLAGS) -o $(CLIENT) $(LIB)

$(SERVER): $(BUILDDIR)
	@echo "   Build mode : Building target $@ ..."
	$(CC) $(SERVER_SRC) $(CFLAGS) -o $(SERVER) $(LIB)

$(BUILDDIR):
	mkdir $(BUILDDIR)

clean:
	$(RM) $(CLIENT)
	$(RM) $(SERVER)

.PHONY: clean