#ifndef _ECHD_OPENSSL_H_
#define _ECHD_OPENSSL_H_
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/x509.h>

EVP_PKEY* gen_ec_keypair();
unsigned char *key_agreement_ecdh(EVP_PKEY *pkey, EVP_PKEY *peerkey,size_t *secret_len);
void print_hex(char *msg, unsigned char *buf, size_t len);
int get_ec_pubkey_der(EVP_PKEY *pkey, unsigned char **ppubkey, size_t *p_len);
int get_ec_pubkey_from_der(EVP_PKEY **ppkey, unsigned char *ppubkey, size_t p_len);
void print_ec_pubkey(char *msg, EVP_PKEY *pkey);

#endif //_ECHD_OPENSSL_H_

