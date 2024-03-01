#include<stdio.h>
#include<string.h>

void printarg(char *inp) 
{
    char str[60];

    strcpy(str, inp);
}

int main(int argc,char *argv[])
{
    printarg(argv[1]);
    return 0;
}

