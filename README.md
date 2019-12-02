[![Deploy Status](https://github.com/io12/pwninit/workflows/deploy/badge.svg)](https://github.com/io12/pwninit/actions)
[![](https://img.shields.io/crates/v/pwninit)](https://crates.io/crates/pwninit)
[![](https://docs.rs/pwninit/badge.svg)](https://docs.rs/pwninit)

# `pwninit`

A tool for automating starting binary exploit challenges

## Features

- Set challenge binary to be executable
- Download a linker (`ld-linux.so.*`) that can segfaultlessly `LD_PRELOAD` the provided libc
- Download debug symbols and unstrip the libc
- Fill in a template pwntools solve script

## Usage

### Short version

Run `pwninit`

### Long version

Run `pwninit` in a directory with the relevant files and it will detect which ones are the binary, libc, and linker. If the detection is wrong, you can specify the locations with `--bin`, `--libc`, and `--ld`.

#### Custom `solve.py` template

If you don't like the default template, you can use your own. Just specify `--template-path <path>`. Check [template.py](src/template.py) for the template format. The names of the `exe`, `libc`, and `ld` bindings can be customized with `--template-bin-name`, `--template-libc-name`, and `--template-ld-name`.

##### Persisting custom `solve.py`

You can make `pwninit` load your custom template automatically by adding an alias to your `~/.bashrc`.

###### Example

```bash
alias pwninit='pwninit --template-path ~/.config/pwninit-template.py --template-bin-name e'
```

## Install

### Arch Linux

Install [`pwninit`](https://aur.archlinux.org/packages/pwninit/) or
[`pwninit-bin`](https://aur.archlinux.org/packages/pwninit-bin/) from the AUR.

### Download

You can download non-GMO statically-linked [musl](https://www.musl-libc.org/)
binaries from the [releases page](https://github.com/io12/pwninit/releases).

### Using cargo

```sh
cargo install pwninit
```

The binary will be placed in `~/.cargo/bin`.

Note that `openssl`, `liblzma`, and `pkg-config` are required for the build.

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
#!/usr/bin/env python3

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
