#include "signtool.h"

unsigned char iv[]= {0x3d,0xaf,0xba,0x42,0x9d,0x9e,0xb4,0x30,
					0xb4,0x22,0xda,0x80,0x2c,0x9f,0xac,0x41};

void sign_exec(t_signtool *signtool)
{
	EVP_PKEY_CTX *ctx;
	// private key
	EVP_PKEY *signing_key = PEM_read_PrivateKey(signtool->key_fp, NULL, NULL, NULL);

	ctx = EVP_PKEY_CTX_new(signing_key, NULL);
	if (!ctx)
		error("ctx new error");
	if (EVP_PKEY_sign_init(ctx) <= 0)
		error("ctx init error");
	if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
		error("ctx rsa padding error");
	if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0)
		error("ctx set signature error");

	unsigned char *sign;
	size_t signlen;
	// Determine sign buffer length
	if (EVP_PKEY_sign(ctx, NULL, &signlen, signtool->exec, strlen((char *)signtool->exec)) <= 0)
		error("determine sign length error");
	sign = OPENSSL_malloc(signlen);
	if (!sign)
		error("sign malloc error");
	if (EVP_PKEY_sign(ctx, sign, &signlen, signtool->exec, strlen((char *)signtool->exec)) <= 0)
		error("make sign error");

	if (add_section(signtool->exec_filename, sign, signlen) < 0)
		error("add signature error");
}

void verify_exec(t_signtool *signtool)
{
	EVP_PKEY_CTX *ctx;
	// public key
	EVP_PKEY *verify_key = PEM_read_PUBKEY(signtool->key_fp, NULL, NULL, NULL);

	ctx = EVP_PKEY_CTX_new(verify_key, NULL);
	if (!ctx)
		error("ctx new error");
	if (EVP_PKEY_verify_init(ctx) <= 0)
		error("ctx init error");
	if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
		error("ctx rsa padding error");
	if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0)
		error("ctx set signature error");
	
	unsigned char *sign;
	size_t signlen;
	/* Perform operation */
	int ret = EVP_PKEY_verify(ctx, sign, signlen, signtool->exec, strlen((char *)signtool->exec));

	if (ret == 1)
		printf("success");
	else if (ret == 0)
		printf("fail");
	else if (ret < 0)
		error("verify error");
}
