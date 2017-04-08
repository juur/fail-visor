#include <stdio.h>

int main(int ac, char *av[])
{
	printf("%x\n", 0xff & 0xf0);
	printf("%x\n", 0xf0 >> 4);
}

