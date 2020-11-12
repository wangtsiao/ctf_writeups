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

### 支持与联系

我是一名普普通通的`Bachelor`学生，为了强化理解学习的知识，所以开始了我漫长的自学道路，你在这个网页看到的所有内容，都是我在网上探索，自学而来的。如果觉得本文档对你的学习有帮助，也谢谢`star`本仓库。联系到我有很多种方式，欢迎大家用各种途径留言，有时间的话，我会尽量回复你的留言或问题。以下是几种可以讨论的方式:

- Emalil: wang.qi.ao@qq.com
- Github: https://github.com/wangtsiao

