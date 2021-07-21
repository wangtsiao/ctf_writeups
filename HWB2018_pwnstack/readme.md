# HWB2018_pwnstack

护网杯pwn的签到题目，简单的栈溢出，不同与以往的是，这里用了浮点数比较。

```c
printf("HuWangBei CTF 2018 will be getting start after %lu seconds...\n", 0LL, 1.797693134862316e308);
puts("But Whether it starts depends on you.");
read(0, &buf, 0x28uLL);
if ( v7 != 0x7FFFFFFFFFFFFFFFLL || v8 != 0.1 )
{
  puts("Try again!");
}
else
{
  printf("HuWangBei CTF 2018 will be getting start after %g seconds...\n", &buf, v8);
  system("/bin/sh");
}
```

x86汇编语言层面在对浮点数进行比较时，使用了一下一段代码。`ucomisd` - 无序比较标量双精度浮点值并设置 EFLAGS。此外，PF奇偶标志位：反映运算结果低8位中“bai1”的个数。“1”的个数为偶数，du则PF置1，否则置0，如果`PF`为1则`jp`跳转指令可以跳转到目标位置 `jnp`相反。

![image-20201112093855146](readme.assets/image-20201112093855146.png)

这里是[exploit.py](./exp.py)。

