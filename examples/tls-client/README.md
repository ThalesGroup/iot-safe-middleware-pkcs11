# TLS Client Example

This example demonstrates a simple TLS client that connects to a TLS server, verifies the server's certificate, and sends a message to the server.

## Dependencies

To build and run this example, you need the following dependencies:

- OpenSSL library (libssl-dev)
- GCC compiler

You can install these dependencies using the following command:

```bash
sudo apt-get install libssl-dev gcc
```

## Build

To build the TLS client and server, navigate to the example directory and run the following command:

```bash
make
```

This will generate the `tls-client` and `tls-server` executables in the `build` directory.

## Run

Before running the TLS client and server, you need to generate the necessary certificates. Run the following command:

```bash
make gen-cert-iot
```

This will generate the CA certificate, server certificate, and client certificate in the `build` directory.

To run the TLS server, execute the following command:

```bash
./build/tls-server
```

In a separate terminal, run the TLS client:

```bash
./build/tls-client
```

The client will connect to the server, verify the server's certificate, send a message to the server, and receive a response.