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

void read_files(t_signtool *signtool)
{
	read_key(signtool);
	read_exec(signtool);
}

void read_key(t_signtool *signtool)
{
	fseek(signtool->key_fp, 0, SEEK_END);
	signtool->key_length = ftell(signtool->key_fp);
	rewind(signtool->key_fp);

	signtool->key = (unsigned char*)malloc(sizeof(unsigned char) * (signtool->key_length + 1));
	if (signtool->key == NULL)
		error("key malloc error");	
	memset(signtool->key, 0, signtool->key_length + 1);

	size_t count = 0;
	while(1)
	{
		size_t len = fread(signtool->key + count, sizeof(unsigned char), 4, signtool->key_fp);
		if (len < 0)
			error("key file read error");
		if (len == 0)
			break;
	    count += len;
	}
	signtool->key[count] = '\0';
}

void read_exec(t_signtool *signtool)
{
	fseek(signtool->exec_fp, 0, SEEK_END);
	signtool->exec_length = ftell(signtool->exec_fp);
	rewind(signtool->exec_fp);

	signtool->exec = (unsigned char*)malloc(sizeof(unsigned char) * signtool->exec_length);
	if (signtool->exec == NULL)
		error("infile malloc error");
	memset(signtool->exec, 0, signtool->exec_length);

	size_t count = 0;
	while(1)
	{
		size_t len = fread(signtool->exec + count, sizeof(unsigned char), 4, signtool->exec_fp);
		if (len < 0)
			error("infile read error");
		if (len == 0)
			break;
	    count += len;
	}
	signtool->exec[count] = '\0';
}
