#include "signtool.h"

void open_key(t_signtool *signtool, char *filename)
{
	FILE *fp = fopen(filename, "r");
	if (fp == NULL)
		error("key file error");
	signtool->key_fp = fp;
}

void open_exec(t_signtool *signtool, char *filename)
{
	FILE *fp = fopen(filename, "r");
	if (fp == NULL)
		error("in file error");
	signtool->exec_fp = fp;
}

void open_files(t_signtool *signtool)
{
	open_key(signtool, signtool->key_filename);
	open_exec(signtool, signtool->exec_filename);
}
