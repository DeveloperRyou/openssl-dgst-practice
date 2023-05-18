#include "signtool.h"

void error(char *msg)
{
	printf("ERROR\n");
	//printf("%s\n", msg);
	(void)msg;
	exit(1);
}
