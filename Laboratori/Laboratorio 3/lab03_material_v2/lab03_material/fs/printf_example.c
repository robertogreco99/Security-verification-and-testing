#include <stdio.h>

int main()
{
	int a=1,b=2,c=3;
	int n1,n2;
	
	printf("%d %d %d\n",a,b,c);
	printf("%d %d \n",a,b,c);
	printf("%d %d %d\n",a,b);
	printf("%2$d %3$d %1$d\n",a,b,c);
	
	printf("The printf can store the number of bytes written to stdout up to this point%n (this number is stored in n1) and the ones up to this point%n (this number is stored in n2)\n", &n1, &n2);
	printf("n1: %d, n2: %d\n",n1,n2);
	printf("n1: %d, n2: %d\n",n1,n2);
	
	return 0;
}
