/***
 * This sample code to test ECDHE is from the OpenSSL Wiki Documentation 
 * 	https://wiki.openssl.org/index.php/Elliptic_Curve_Diffie_Hellman 
 * 
 * 
 */

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/x509.h>
#include "ecdh_openssl.h"

/***
 *  Generate a EC Keypair to be used for ECDHE
 * 
 *  Returns on Success
 * 		EVP_PKEY *ptr
 * 
 * 
 */

 
EVP_PKEY* gen_ec_keypair()
{
	EVP_PKEY_CTX *pctx, *kctx;

	EVP_PKEY *pkey = NULL, *params = NULL;
	/* NB: assumes pkey, peerkey have been already set up */

	/* Create the context for parameter generation */
	if(NULL == (pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))) 
	{
		printf("Error creating context \n");
		return NULL;
	}

	/* Initialise the parameter generation */
	if(1 != EVP_PKEY_paramgen_init(pctx))  
	{
		EVP_PKEY_CTX_free(pctx);
		printf("Error initializing parameters for key generation.\n");
		return NULL;
	}

	/* We're going to use the ANSI X9.62 Prime 256v1 curve */
	if(1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1))  
	{
		EVP_PKEY_CTX_free(pctx);
		printf("Error setting curve id  NSI X9.62 Prime 256v1 curve.\n");
		return NULL;
	}

	/* Create the parameter object params */
	if (!EVP_PKEY_paramgen(pctx, &params)) 
	{
		EVP_PKEY_CTX_free(pctx);
		printf("Error setting curve id  NSI X9.62 Prime 256v1 curve.\n");
		return NULL;
	}


	/* Create the context for the key generation */
	if(NULL == (kctx = EVP_PKEY_CTX_new(params, NULL)))  
	{
		EVP_PKEY_free(params);
		EVP_PKEY_CTX_free(pctx);
		printf("Error reate the context for the key generation .\n");
		return NULL;
	}

	/* Generate the key */
	if(1 != EVP_PKEY_keygen_init(kctx))  
	{
		EVP_PKEY_free(params);
		EVP_PKEY_CTX_free(pctx);
		printf("Error Init Generate the key  .\n");
		return NULL;
	}
	if (1 != EVP_PKEY_keygen(kctx, &pkey)) 
	{
		EVP_PKEY_free(params);
		EVP_PKEY_CTX_free(pctx);
		printf("Error Generating the key  .\n");
		return NULL;
	}
	else
	{
		EVP_PKEY_free(params);
		EVP_PKEY_CTX_free(pctx);
		return pkey;
	}
}


/***
 *  Perform a ECDH Key Agreement to derive Secret Key
 * 
 *  Returns on Success
 * 		Secret key buf
 * 
 * 
 */

unsigned char *key_agreement_ecdh(EVP_PKEY *pkey, EVP_PKEY *peerkey,size_t *secret_len)
{
	EVP_PKEY_CTX *ctx;
	unsigned char *secret;
	/* Create the context for the shared secret derivation */
	if(NULL == (ctx = EVP_PKEY_CTX_new(pkey, NULL))) 
	{
		printf("Error creating context for shared secret derivation. \n");
		return NULL;
	}

	/* Initialise */
	if(1 != EVP_PKEY_derive_init(ctx)) 
	{
		printf("Error initializing shared secret derivation. \n");
		EVP_PKEY_CTX_free(ctx);
		return NULL;
	}

	/* Provide the peer public key */
	if(1 != EVP_PKEY_derive_set_peer(ctx, peerkey))  
	{
		printf("Error providing the peer public key  \n");
		EVP_PKEY_CTX_free(ctx);
		return NULL;
	}
	/* Determine buffer length for shared secret */
	if(1 != EVP_PKEY_derive(ctx, NULL, secret_len)) 
	{
		printf("Error determining buffer length for shared secret  \n");
		EVP_PKEY_CTX_free(ctx);
		return NULL;
	}

	/* Create the buffer */
	if(NULL == (secret = OPENSSL_malloc(*secret_len))) 
	{
		printf("Error allocating memory for secret , len=%d \n",(int)*secret_len);
		EVP_PKEY_CTX_free(ctx);
		return NULL;
	}


	/* Derive the shared secret */
	if(1 != (EVP_PKEY_derive(ctx, secret, secret_len))) 
	{
		printf("Error derive the shared secret \n");
		EVP_PKEY_CTX_free(ctx);
		return NULL;
	}

	EVP_PKEY_CTX_free(ctx);

 
	/* Never use a derived secret directly. Typically it is passed
	 * through some hash function to produce a key */
	return secret;
}

/***
 *  Get DER (Uncompressed format : 0x04 X (32 Byets), Y (32 Bytes)) from EVP_PKEY / EC_KEY a EC Keypair to be used for ECDHE
 * 
 *  Returns on Success
 * 		0 	
 * 	and **ppubkey filled with ptr to DER of Public Key
 * 
 * 
 */

int get_ec_pubkey_der(EVP_PKEY *pkey, unsigned char **ppubkey, size_t *p_len)
{
	EC_KEY *parsedKey = NULL;
	parsedKey = EVP_PKEY_get0_EC_KEY(pkey);
	if (parsedKey != NULL)
	{
    	*p_len = EC_KEY_key2buf(parsedKey, POINT_CONVERSION_UNCOMPRESSED,
                                          ppubkey, NULL);
		return 0; 
	}
	return -1;
}


/***
 *  Construct public ker from DER (Uncompressed format : 0x04 X (32 Byets), Y (32 Bytes)) into EVP_PKEY / EC_KEY a EC Keypair to be used for ECDHE
 * 
 *  Returns on Success
 * 		0 	
 * 	and EVP_PKEY *pkey filled with Public Key
 * 
 * 
 */
int get_ec_pubkey_from_der(EVP_PKEY **ppkey, unsigned char *ppubkey, size_t p_len)
{
	int ret = 0; // Error by default
	EC_KEY *eckey = EC_KEY_new();
    EC_GROUP *ecgroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_set_group(eckey, ecgroup);
    EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);
	EC_POINT *ecpoint = EC_POINT_new(ecgroup);
	ret = EC_POINT_oct2point(ecgroup, ecpoint, ppubkey, p_len, NULL);
	  
	ret = 	EC_KEY_set_public_key(eckey, ecpoint);
	*ppkey = EVP_PKEY_new();
	ret = 	EVP_PKEY_set1_EC_KEY(*ppkey, eckey);

	if (ret == 1)
		return 0; 
	return -1;
}

#if 0
void print_hex(char *msg, unsigned char *buf, size_t len)
{
	printf("%s", msg);
	for (size_t i =0; i < len; i++)
		printf("%02X", buf[i]);
	printf("\n");
}

void print_ec_pubkey(char *msg, EVP_PKEY *pkey)
{
 
    unsigned char *ppubkey;
    size_t p_len =0;
	
	if  (get_ec_pubkey_der(pkey, &ppubkey, &p_len) != -1)
	{
		print_hex(msg, ppubkey, p_len);
		//EC_KEY_free(parsedKey);
		OPENSSL_free(ppubkey);
	}
	else
	{
		printf ("Error extracting public\n");
	}
}

int main(int argc, char** argv)
{
	size_t secret_len = 32;
	EVP_PKEY *alice_key = NULL, *bob_key, *params = NULL;
	//unsigned char * secret = ecdh(&secret_len);
	// Generate Alice's key
	alice_key = gen_ec_keypair();
	if (alice_key == NULL)
		printf("Error generating Alice's key \n");
	
	print_ec_pubkey("Alice's Public Key = ", alice_key);
	// Generate Bob's key
	bob_key = gen_ec_keypair();
	if (bob_key == NULL) {
		printf("Error generating Bob's key \n");
		EVP_PKEY_free(alice_key);
		return -1;
	}
	print_ec_pubkey("Bob's Public Key = ", bob_key);

	/// TEST
    EVP_PKEY *ppkey_recontructed_bob = NULL;
	unsigned char *ppubkey = NULL;
    size_t p_len =0;
	
	if  (get_ec_pubkey_der(bob_key, &ppubkey, &p_len) != -1)
	{
		
		int ret = get_ec_pubkey_from_der(&ppkey_recontructed_bob, ppubkey,p_len);
		if (ret == 0)
			printf("EVP Key Reconstructed \n");
		//EC_KEY_free(parsedKey);
		//EVP_PKEY_free(ppkey_recontructed);
		OPENSSL_free(ppubkey);
	}

	

	/// End TEST

	// Alice derive Key
	unsigned char *alice_secret = key_agreement_ecdh(alice_key, ppkey_recontructed_bob,&secret_len);
	if (alice_secret != NULL) 
	{
		print_hex("Alice's Secret = ", alice_secret, secret_len);
		OPENSSL_free(alice_secret);  
	}
	// Bob derive Key
	unsigned char *bob_secret = key_agreement_ecdh(bob_key,alice_key,&secret_len);
	if (bob_secret != NULL) 
	{
		print_hex("Bob's Secret   = ", bob_secret, secret_len);
		OPENSSL_free(bob_secret);  
	}

	EVP_PKEY_free(alice_key);
	EVP_PKEY_free(bob_key);
	return 0;
}
#endif