#include "signtool.h"

int main(int argc, char **argv)
{
	if (argc != 6)
		error("Arguments error");

	t_signtool signtool;
	
	init_signtool(&signtool);
	parse_operator(&signtool, argv);
	open_files(&signtool);
	read_files(&signtool);

	if (signtool.operator == SIGN)
		sign_exec(&signtool);
	else if (signtool.operator == VERIFY)
		verify_exec(&signtool);
	else
		error("Invalid operator");

	free_signtool(&signtool);
	return (0);
}
