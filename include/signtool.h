#ifndef signtool_H
# define signtool_H

# include <stdio.h>
# include <string.h>
# include "csi4109.h"
# include <openssl/pem.h>
# include <openssl/evp.h> 
# include <openssl/rsa.h>
# include <openssl/err.h>

# define SIGN 0
# define VERIFY 1

typedef struct s_signtool
{
	FILE *key_fp;
	FILE *exec_fp;
	char *key_filename;
	char *exec_filename;
	unsigned char *exec;
	size_t exec_length;
	int operator;
}	t_signtool;

// parse.c
void parse_operator(t_signtool *signtool, char **operator);

// file.c
void open_key(t_signtool *signtool, char *filename);
void open_exec(t_signtool *signtool, char *filename);
void open_files(t_signtool *signtool);
void read_exec(t_signtool *signtool);

// init.c
void init_signtool(t_signtool *signtool);
void free_signtool(t_signtool *signtool);

// signtool.c
void sign_exec(t_signtool *signtool);
void verify_exec(t_signtool *signtool);

// print.c
void error(char *msg);

#endif