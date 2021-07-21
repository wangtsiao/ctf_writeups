# Anheng201810_whoami

### 题目信息：

```c
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

### 程序概述：

初学者一开始分析该题目可能会坠入分析逻辑的陷阱，实际上pwn题只需要找准漏洞点，思考利用方法即可。程序在`input name`逻辑中使用gets函数，同时程序中还有`system("/bin/sh")`，入门级别的栈溢出。

这里是[exploit.py](./exp.py)

