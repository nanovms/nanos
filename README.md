# nanos

[![CircleCI](https://circleci.com/gh/nanovms/nanos.svg?style=svg)](https://circleci.com/gh/nanovms/nanos)

Read more about the Nanos Charter [here](CHARTER.md).

### Building/Running

Please use [https://github.com/nanovms/ops](ops) unless you are planning
on modifying nanos.

If you are in a vm already (which is a bad idea) you'll need to specify
that you don't want hardware acceleration:

```
make run no-accel
```

For Nanos try running the first example first:
```
make run
```

To try a different target currently found in examples/ you can:

1) cp the manifest file to target.manifest
2) add your code and set a target in examples/Makefile

```
TARGET=mynewtarget make run
```

### TFS

TFS is the current filesystem utilized by Nanos.

### Optional Flags

thread tracing:

```
futex_trace: t
```

syscall tracing:

```
debugsyscalls: t
```

stackdump:

```
fault: t
```

Read more about Security [here](SECURITY.md).

[Architecture](https://github.com/nanovms/nanos/wiki/Architecture)

[Debugging Help](https://github.com/nanovms/nanos/wiki/debugging)

[Manual Networking Setup](https://github.com/nanovms/nanos/wiki/networking-setup)

[Build Envs](https://github.com/nanovms/nanos/wiki/Build-Envs)

[Reference Materials](https://github.com/nanovms/nanos/wiki/reference-materials)
