# nanos

[![CircleCI](https://circleci.com/gh/nanovms/nanos.svg?style=svg)](https://circleci.com/gh/nanovms/nanos)

<p align="center">
  <img src="https://repository-images.githubusercontent.com/115159616/44eb1980-a6f4-11e9-9e7b-df7adf662967" style="width:200px;"/>
</p>

Nanos is a new kernel designed to run one and only one application in a
virtualized environment. It has several constraints on it compared to a
general purpose operating system such as Windows or Linux - namely it's
a single process system with no support for running multiple programs
nor does it have the concept of users or remote administration via ssh.

Read more about the Nanos Charter [here](CHARTER.md).

### Building/Running

It is highly encouraged to use [ops](https://github.com/nanovms/ops) to build and run your applications using Nanos unless you are planning
on modifying Nanos. OPS provides sensible defaults for most users and
incorporates our understanding of how to appropriately best use Nanos.
It is also currently highly coupled to Nanos.

If you are running in a vm already (which is a bad idea) you'll need to specify
that you don't want hardware acceleration. For instance you can run
Nanos in virtualbox on a mac but it will be slow and hard to configure.

You can build and run on mac and linux. Nanos supports KVM on linux and
HVF on osx currently for acceleration. OPS has facilities to deploy to
the public clouds (AWS/GCE).

To build:
```
make run no-accel
```

### Tests

To run tests:
```
make test-noaccel
```

### Development Running Instructions

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

You may also wish to use [https://github.com/nanovms/ops](ops) to
develop locally. If that's the case a commonly used idiom is to simply
copy the 3 required files to an appropriate release:

```
cp output/mkfs/bin/mkfs ~/.ops/0.1.17/.
cp output/boot/boot.img ~/.ops/0.1.17/.
cp output/stage3/bin/stage3.img ~/.ops/0.1.17/.
```

### Contributing

#### Pull Requests

We accept pull requests as long as it conforms to our style and stated
goals. We may reject prs if they violate either of these conditions.

If you are planning on spending more than a day to fix something
it's probably wise to approach the topic in an issue with your planned
fix before commiting to work.

Also, NanoVMs has paid kernel engineers with internal roadmaps so it's
wise to check in with us first before grabbing a tkt. Tickets tagged
'low-priority' have a lower probability of collision.

#### Reporting Bugs

Please scan the issue list first to see if we are already tracking the
bug.

Please attach debugging output ('-d' in ops). Please provide the
config.json and anything else that allows us to reproduce the issue.

### TFS

TFS is the current filesystem utilized by Nanos.

### Optional Manifest Debugging Flags

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

### Getting Help

We run a public mailing list at:

  nanos-users@nanovms.com

for general questions. If you'd like more in-depth help reach out to the
nanovms folks via drift or email engineering.
