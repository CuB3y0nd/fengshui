# Level 0

## Information

- Category: Pwn

## Description

> None.

## Write-up

This is probably the easiest stack fengshui challenge.

This challenge gave us `pop rax; ret` gadget, but cannot control any other registers, like `rdi` etc.

Only `0x20` bytes read with `0x10` bytes buffer, so we can only write `0x10` bytes data each time, and then overwrite `rbp` and `rip`.

So, the idea is use sigreturn to execute `execve("/bin/sh", NULL, NULL)`, and the first thing we have to do it figure out how to implement the arbitrary size read, such that we can send the full sigreturn structure, then construct a sigreturn by utilize the `pop rax; ret` gadget.

The memory layout should be looks like:

```plaintext showLineNumbers=false
# pop rax; ret
# 0xf
# syscall
# sigreturn frame
```

Now, let's think about how to achieve an arbitrary size read. Assume following memory dump is the stats of the first time read, because we want get an arbitrary size consistent read, so we cannot chain the next `read` gadget write to `0x404038` directly.

```plaintext showLineNumbers=false
pwndbg> x/10gx 0x404028
0x404028: 0x4141414141414141 0x4141414141414141
0x404038: 0x0000000000404048 0x0000000000401133
0x404048: 0x0000000000000000 0x0000000000000000
0x404058: 0x0000000000000000 0x0000000000000000
0x404068: 0x0000000000000000 0x0000000000000000
```

If we directly write to the next consistent address, it'll cause `read` return to `0x4242424242424242` and crash the program.

```plaintext showLineNumbers=false
pwndbg> x/10gx 0x404028
0x404028: 0x4141414141414141 0x4141414141414141
0x404038: 0x4242424242424242 0x4242424242424242
0x404048: 0x0000000000404058 0x0000000000401133
0x404058: 0x0000000000000000 0x0000000000000000
0x404068: 0x0000000000000000 0x0000000000000000
```

The way to bypass is fairly simple, just avoid corrupt the return address later used by `read`. First, we read some junk bytes to `0x404048` to keeping the rop chain alive so we can read more data.

```plaintext showLineNumbers=false
pwndbg> x/10gx 0x404028
0x404028: 0x4141414141414141 0x4141414141414141
0x404038: 0x0000000000404058 0x0000000000401149
0x404048: 0x5858585858585858 0x5858585858585858
0x404058: 0x0000000000404048 0x0000000000401133
0x404068: 0x0000000000000000 0x0000000000000000
```

Then write the actual data which we needed to `0x404038`.

```plaintext showLineNumbers=false
pwndbg> x/10gx 0x404028
0x404028: 0x4141414141414141 0x4141414141414141
0x404038: 0x4242424242424242 0x4242424242424242
0x404048: 0x0000000000404048 0x0000000000401133
0x404058: 0x0000000000404048 0x0000000000401149
0x404068: 0x0000000000000000 0x0000000000000000
```

Finally, repeat the same way to achieve arbitrary size read.

As for how to get the `syscall; ret` gadget, we can utilize `read@got`, checking instructions nearby `read`, you can found some of them.

So the final memory layout should be:

```plaintext showLineNumbers=false
# pop rax; ret
# 0xf
# read@plt (syscall)
# sigreturn frame
```

And the final strategy is:

1. Pre-place `pop rax; ret` chain for execute sigreturn
2. Place sigreturn frame beside the chain (actually you can put it anywhere, just have to manually pivot, to make sure the `rsp` points to the frame)
3. Modify `read@got` points to `syscall; ret` gadget
4. Pivot back to the start of the ROP chain
