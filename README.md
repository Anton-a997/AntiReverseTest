# AntiReverseTest
Testing software protection methods against reverse engineering for programs developed in a compiled programming language

## Introduction
For demonstration purposes, a simple console application was developed that calculates MD5 and SHA-1 checksums of strings entered by the user.
The application employs two protection methods:
1. Guarded memory pages – protection against memory dumping
2. Calling the target function via a decoy call to another function vulnerable to buffer overflow – complicating algorithm recovery during reverse engineering.

The provided implementation of these methods has many shortcomings, is not complete, and serves only for demonstration. The program was developed exclusively for research purposes.

## Guarded Memory Pages
To protect against process memory dumping, we use guarded memory pages. Pages containing the protected code are packed (in our project, we simply use XOR) and marked with the PAGE_GUARD attribute when the program starts. When a guarded page is accessed, an EXCEPTION_GUARD_PAGE exception is raised. Our task is to handle this exception, unpack the protected code, and pass execution control to the program code.

To set up memory page protection, we use a TLS callback — a function executed by the operating system in the context of the process before execution begins at the entry point.
The function for installing a custom exception handler has the following C prototype:
```
EXTERN_C VOID set_exception_handler(DWORD address);
```
and is implemented entirely in MASM in the set_exception_handler.asm file.

This function installs the user_exception_dispatcher() function implemented in the project as the first and only exception handler in the SEH chain. The Next field pointing to the next handler is set to the value 0xFFFFFFFF — indicating the end of the chain.

![image](https://user-images.githubusercontent.com/88583217/204514298-b672215d-e312-46da-804a-02bb280c5ee8.png)

For clarity, the handler outputs a message when guarded pages are accessed, then unpacks the code and returns control.

![image](https://user-images.githubusercontent.com/88583217/204514693-a99ff5c8-ec9f-4f3a-85f2-2ddb79e60d6d.png)

Let's compare in IDA Pro the disassembled code of the SHA1Init() function at address 0x00413410 in the original executable file and in the dump captured by Scylla.

![image](https://user-images.githubusercontent.com/88583217/204515165-8d2796e7-eece-4cd4-90fb-9fa505ee6bd9.png)

We see that instead of the function code, the disassembler sees "garbage" — packed code.

Memory page protection can be an effective defense against dumping. The implementation presented in this work is not a full-fledged protection by itself, but merely demonstrates the mechanism under study. For effective protection, this approach is intended to be used in packers so that the executable file itself already contains packed code, and at startup only the PAGE_GUARD attribute is set on the protected pages. In the presented implementation, however, the code is "packed" (encoded with an XOR operation) and pages are protected at process startup, while the original code is contained in the file in plaintext.

## Function Call via Buffer Overflow
Let's replace the standard call to the md5() function in the program with a combination of a buffer overflow and a RETN instruction call. This programming technique allows executing arbitrary code when exploiting buffer overflow vulnerabilities. In doing so, there is no need to inject code into the address space; it is selected in parts from the existing code in such a way that each part ends with a RETN return instruction. In our case, this prepared code is the md5() function, and the f_rop() function, vulnerable to a buffer (stack) overflow, is implemented in assembly in the f_rop.asm file.

We declare the C prototype of this function as follows:
```
EXTERN_C VOID f_rop(char* buf, char* str, size_t len);
```
The function takes 3 arguments: the first is the string that will overflow the stack, and the other two are for the md5() function. However, in its definition we describe it as a function without parameters. This is because the compiler in Visual Studio automatically adds a prologue to functions that have parameters:
```
PUSH EBP
MOV EBP, ESP
```
This code creates a local frame on the stack, which is used by the function to work with local variables, saving the old value of EBP on the stack beforehand. This would hinder our exploitation of the overflow. The function code simply copies the buf string into a small 4-byte buffer, followed immediately by the function's return address. The buf string is longer than 4 bytes, which causes the return address to be overwritten.

Before calling the f_rop() function, it is necessary to prepare this very string s_rop to pass to the function. Bytes 4 through 7 are filled with the bytes of the md5() function address. There is no need to know its address in advance; it is determined at runtime.
```
// configure the s_rop buffer to call the md5() function via buffer overflow in f_rop()
DWORD p_md5 = (DWORD)&md5;
s_rop[4] = (CHAR) * (PBYTE)&p_md5;
s_rop[5] = (CHAR) * ((PBYTE)&p_md5 + 1);
s_rop[6] = (CHAR) * ((PBYTE)&p_md5 + 2);
s_rop[7] = 0;
```
After that, you simply need to replace the call:
```
md5(msg, len);
```
with the call:
```
f_rop(s_rop, msg, len);
```
When an MD5 checksum calculation is requested in the program, f_rop() is called as described above. In disassembled form, it looks like this:

![image](https://user-images.githubusercontent.com/88583217/204517777-68de3e7b-45b8-4c34-8e0a-029f5d5eb01a.png)

The parameters passed to the function reside on top of the stack in accordance with the __cdecl calling convention. Then the f_rop() function code allocates 4 bytes on top of the stack to copy the s_rop string, saves its address in the EDX register, and overwrites the string address on the stack with the return address, duplicating it. We need this so as not to lose the address where control should be returned after executing the "arbitrary" code. The stack before copying the string is shown in the figure below.

![image](https://user-images.githubusercontent.com/88583217/204518147-7af855b6-3070-462f-954c-8739bf118568.png)

After copying, the first return address will be overwritten. The overflowed stack with the prepared sequence of return addresses is shown in the figure below. The highlighted value in the figure is the address of the md5() function. Control transfers will now be performed using the RETN instruction.

![image](https://user-images.githubusercontent.com/88583217/204518323-4b15240b-58f0-4e2c-affe-57c17c24a163.png)

All that remains is to free the allocated 4-byte buffer and execute RETN, transferring execution to the md5() function. By this point, the stack will look as it should for a normal function call.

![image](https://user-images.githubusercontent.com/88583217/204518429-b68cad60-6746-4ebf-b10a-8a313980d258.png)

Then normal program execution continues, returning control to the call site.

Such an approach can complicate program analysis and algorithm recovery, as this method of calling a function is completely non-obvious to a disassembler. Using this method requires careful debugging and testing. This approach can mislead a researcher even when source code is available, as seen in the call graph example in Understand.

![image](https://user-images.githubusercontent.com/88583217/204518913-cb21084d-8cbb-435c-984f-615fa7d635ac.png)

