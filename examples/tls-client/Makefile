
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


gen-cert:
	$(RM) $(BUILDDIR)/*.pem
	@echo "Generate CA private key"
	openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out $(BUILDDIR)/ca-key.pem
	@echo "Generate CA certificate (valid for 365 days)"
	openssl req -x509 -new -key $(BUILDDIR)/ca-key.pem -out $(BUILDDIR)/ca-cert.pem -days 365 -subj "/C=US/ST=State/L=City/O=MyCA"

	@echo "Generate server private key"
	openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out $(BUILDDIR)/server-key.pem
	@echo "Create a certificate signing request (CSR) for the server"
	openssl req -new -key $(BUILDDIR)/server-key.pem -out $(BUILDDIR)/server-csr.pem -subj "/C=US/ST=State/L=City/O=Server"
	@echo "Sign the server CSR with our CA"
	openssl x509 -req -in $(BUILDDIR)/server-csr.pem -CA $(BUILDDIR)/ca-cert.pem -CAkey $(BUILDDIR)/ca-key.pem -CAcreateserial -out $(BUILDDIR)/server-cert.pem -days 365

	@echo "Generate client private key"
	openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out $(BUILDDIR)/client-key.pem
	@echo "Create a certificate signing request (CSR) for the client"
	openssl req -new -key $(BUILDDIR)/client-key.pem -out $(BUILDDIR)/client-csr.pem -subj "/C=US/ST=State/L=City/O=Client"
	@echo "Sign the client CSR with our CA"
	openssl x509 -req -in $(BUILDDIR)/client-csr.pem -CA $(BUILDDIR)/ca-cert.pem -CAkey $(BUILDDIR)/ca-key.pem -CAcreateserial -out $(BUILDDIR)/client-cert.pem -days 365


gen-cert-iot:
	$(RM) $(BUILDDIR)/*.pem
	@echo "Generate CA private key"
	openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out $(BUILDDIR)/ca-key.pem
	@echo "Generate CA certificate (valid for 365 days)"
	openssl req -x509 -new -key $(BUILDDIR)/ca-key.pem -out $(BUILDDIR)/ca-cert.pem -days 365 -subj "/C=US/ST=State/L=City/O=MyCA"
	
	@echo "Generate server private key"
	openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out $(BUILDDIR)/server-key.pem
	@echo "Create a certificate signing request (CSR) for the server"
	openssl req -new -key $(BUILDDIR)/server-key.pem -out $(BUILDDIR)/server-csr.pem -subj "/C=US/ST=State/L=City/O=Server"
	@echo "Sign the server CSR with our CA"
	openssl x509 -req -in $(BUILDDIR)/server-csr.pem -CA $(BUILDDIR)/ca-cert.pem -CAkey $(BUILDDIR)/ca-key.pem -CAcreateserial -out $(BUILDDIR)/server-cert.pem -days 365

	@echo "Create a certificate signing request (CSR) for the client using iot safe"
	openssl req -new -engine pkcs11 -keyform engine -key "pkcs11:id=%30%31" -out $(BUILDDIR)/client-csr.pem -subj "/C=US/ST=State/L=City/O=Client"
	@echo "Sign the client CSR with our CA"
	openssl x509 -req -in $(BUILDDIR)/client-csr.pem -CA $(BUILDDIR)/ca-cert.pem -CAkey $(BUILDDIR)/ca-key.pem -CAcreateserial -out $(BUILDDIR)/client-cert.pem -days 365

clean:
	$(RM) $(CLIENT)
	$(RM) $(SERVER)

.PHONY: clean