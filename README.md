# `pwninit`

A tool for automating starting binary exploit challenges

## Features

- Set challenge binary to be executable
- Download a linker (`ld-linux.so.*`) that can flawlessly `LD_PRELOAD` the provided libc
- Download debug symbols and unstrip the libc
- Fill in a template pwntools solve script

## Usage

### Short version

Run `pwninit`

### Long version

Run `pwninit` in a directory with the relevant files and it will detect which ones are the binary, libc, and linker. If the detection is wrong, you can specify the locations with `--bin`, `--libc`, and `--ld`.

## Install

### Arch Linux

Install [`pwninit`](https://aur.archlinux.org/packages/pwninit/) from the AUR.

### Using cargo

```sh
cargo install pwninit
```

The binary will be placed in `~/.cargo/bin`.

## Example

```sh
$ ls
hunter  libc.so.6  readme

$ pwninit
bin: ./hunter
libc: ./libc.so.6

fetching linker
unstripping libc
setting ./ld-2.23.so executable
writing solve.py stub

$ ls
hunter  ld-2.23.so  libc.so.6  readme  solve.py
```

`solve.py`:
```python
#!/usr/bin/env python2

from pwn import *

exe = ELF("./hunter")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe


def conn():
    if args.LOCAL:
        return process([ld.path, exe.path], env={"LD_PRELOAD": libc.path})
    else:
        return remote("addr", 1337)


def main():
    r = conn()

    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
```
