#include "signtool.h"

void parse_operator(t_signtool *signtool, char **operator)
{
	if (strcmp(operator[1], "sign") == 0)
		signtool->operator = SIGN;
	else if (strcmp(operator[1], "verify") == 0)
		signtool->operator = VERIFY;
	else
		error("Invalid operator");

	for (int i = 2; i < 6; i+=2)
	{
		if (strcmp(operator[i], "-k") == 0)
			signtool->key_filename = operator[i + 1];
		else if (strcmp(operator[i], "-e") == 0)
			signtool->exec_filename = operator[i + 1];
		else
			error("Invalid argument");
	}
}


