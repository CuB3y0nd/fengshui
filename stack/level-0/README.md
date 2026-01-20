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

```plaintext
# pop rax; ret
# 0xf
# syscall
# sigreturn frame
```

As for how to get the `syscall; ret` gadget, we can utilize `read@got`, checking instructions nearby `read`, you can found some of them.

So the final memory layout should be:

```plaintext
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
