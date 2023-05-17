#include "signtool.h"

void init_signtool(t_signtool *signtool)
{
	signtool->operator = 0;
	signtool->key_fp = NULL;
	signtool->exec_fp = NULL;
	signtool->key_filename = NULL;
	signtool->exec_filename = NULL;
	signtool->exec = NULL;
	signtool->exec_length = 0;
}

void free_signtool(t_signtool *signtool)
{
	if (signtool->key_fp != NULL)
		fclose(signtool->key_fp);
	if (signtool->exec_fp != NULL)
		fclose(signtool->exec_fp);
		
	if (signtool->exec != NULL)
		free(signtool->exec);
	init_signtool(signtool);
}

