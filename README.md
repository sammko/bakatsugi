bakatsugi
=========

Bakatsugi is a generic in-memory patching toolkit targeting x86-64 GNU/Linux.
It can be used to modify code of running processes without needing to restart
them. Currently support is implemented for replacing code of entire functions,
either calls to dynamic libraries or functions present in the process itself,
provided debug symbols are available.

This project is in prototype state and should not be used for critical
applications.

Building
--------

Nightly Rust features are used, it is recommended to use the latest available
nightly version. The easiest way to obtain the toolchain is to use [rustup](https://rustup.rs/).
A [rust-toolchain.toml](/rust-toolchain.toml) is provided, so `rustup` should
automatically choose the `nightly` toolchain when working on this project.
Building is only supported under Linux.

In addition, the following tools are required:

  - `nasm`
  - The GNU C toolchain (`ld` and `gcc`)

You then should be able to simply run `cargo build` to obtain a self-contained
executable in `target/debug/bakatsugi`.

Preparing a patch
-----------------

A patch is just a shared object with some additional metadata in the `bakatsugi`
section. The library should contain functions which are to be used as replacements
and should have the same signature as the original counterparts. The patch library
can then be injected into the target process using `bakatsugi`.

A helper C header is provided, which can be used to create the patch library. It
is present in the [c/bakatsugi.h](/c/bakatsugi.h) file. An example patch to replace the libc
`time(2)` function can be found in the [examples/simple-c/libpatch.c](/examples/simple-c/libpatch.c) file.

You can compile it using the associated [Makefile](/examples/simple-c/Makefile).
An example [target program](/examples/simple-c/example.c) is also provided.

This patch library can then be injected into the target process using `bakatsugi`:

```sh
sudo ./target/debug/bakatsugi -p <PID> examples/simple-c/libpatch.so
```

Permissions for `ptrace`-ing the target are required, that means either running as
`root` or the target being owned by the same user and a properly configured `kernel.yama.ptrace_scope` kernel parameter.

You should now see a bunch of debugging information dumped to the `stderr` of the
target process and the patch getting applied.
