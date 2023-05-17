#include "signtool.h"

void sign_exec(t_signtool *signtool)
{
	EVP_PKEY_CTX *ctx = NULL;

	// make md
	unsigned char *md = NULL;
	md = OPENSSL_malloc(SHA256_DIGEST_LENGTH);
	if (!md)
		error("md malloc error");
	bzero(md, SHA256_DIGEST_LENGTH);
	md = SHA256(signtool->exec, signtool->exec_length, md);

	// private key
	EVP_PKEY *signing_key = NULL;
	if (!PEM_read_PrivateKey(signtool->key_fp, &signing_key, NULL, NULL))
		error("private key read error");

	// init ctx
	ctx = EVP_PKEY_CTX_new(signing_key, NULL);
	if (!ctx)
		error("ctx new error");
	if (EVP_PKEY_sign_init(ctx) <= 0)
		error("ctx init error");
	if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
		error("ctx rsa padding error");
	if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0)
		error("ctx set signature error");

	// make sign
	unsigned char *sign = NULL;
	size_t signlen = 0;
	// Determine sign buffer length
	if (EVP_PKEY_sign(ctx, NULL, &signlen, md, SHA256_DIGEST_LENGTH) <= 0)
		error("determine sign length error");

	sign = OPENSSL_malloc(signlen);
	if (!sign)
		error("sign malloc error");
	bzero(sign, signlen);
	
	if (EVP_PKEY_sign(ctx, sign, &signlen, md, SHA256_DIGEST_LENGTH) <= 0)
		error("signing error");

	int ret = add_section(signtool->exec_filename, sign, signlen);
	if (ret < 0)
	{
		printf("%d\n", ret);
		error("add signature error");
	}

	OPENSSL_free(md); md = NULL;
	OPENSSL_free(sign); sign = NULL;
}

void verify_exec(t_signtool *signtool)
{
	EVP_PKEY_CTX *ctx = NULL;
	
	// make md
	unsigned char *md = NULL;
	md = OPENSSL_malloc(SHA256_DIGEST_LENGTH);
	if (!md)
		error("md malloc error");
	bzero(md, SHA256_DIGEST_LENGTH);
	md = SHA256(signtool->exec, signtool->exec_length, md);

	// public key
	EVP_PKEY *verify_key = NULL;
	if (!PEM_read_PUBKEY(signtool->key_fp, &verify_key, NULL, NULL))
		error("public key read error");

	// init ctx
	ctx = EVP_PKEY_CTX_new(verify_key, NULL);
	if (!ctx)
		error("ctx new error");
	if (EVP_PKEY_verify_init(ctx) <= 0)
		error("ctx init error");
	if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
		error("ctx rsa padding error");
	if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0)
		error("ctx set signature error");

	// verify sign
	unsigned char *sign = NULL;
	size_t signlen = 0;
	// Determine sign buffer length
	parse_signature(signtool, NULL, &signlen);
	
	sign = OPENSSL_malloc(signlen);
	if (!sign)
		error("sign malloc error");
	bzero(sign, signlen);
	// Set sign buffer from .signature
	parse_signature(signtool, sign, &signlen);

	int ret = EVP_PKEY_verify(ctx, sign, signlen, md, SHA256_DIGEST_LENGTH);
	if (ret == 1)
		printf("success");
	else if (ret == 0)
		printf("fail");
	else if (ret < 0)
		error("verify error");
		
	OPENSSL_free(md); md = NULL;
	OPENSSL_free(sign); sign = NULL;	
}
