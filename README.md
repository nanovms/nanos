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

### Getting Started

Please use the [ops](https://ops.city) orchestrator to run your applications with Nanos unless you plan on hacking on Nanos itself.

### Building/Running

It is highly encouraged to use [ops](https://github.com/nanovms/ops) to build and run your applications using Nanos unless you are planning
on modifying Nanos. [OPS](https://ops.city) provides sensible defaults for most users and
incorporates our understanding of how to appropriately best use Nanos.
It is also currently highly coupled to Nanos.

If you are running in a vm already (which is a bad idea) you'll need to specify
that you don't want hardware acceleration. For instance you can run
Nanos in virtualbox on a mac but it will be slow and hard to configure.

You can build and run on mac and linux. Nanos supports KVM on linux and
HVF on osx currently for acceleration. [OPS](https://ops.city) has facilities to deploy to
the public clouds (AWS/GCE).

#### Building From Source on a Mac

Install Homebrew:
```
/usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
```

Grab Dependencies:

This installs the correct toolchain and will install an up-to-date qemu.
It is highly recommended to be running the latest qemu otherwise you
might run into issues.

```
brew update && brew install nasm go wget ent
brew tap nanovms/homebrew-x86_64-elf
brew install x86_64-elf-binutils
brew tap nanovms/homebrew-qemu
brew install nanovms/homebrew-qemu/qemu
```

Create a Chroot:
(this isn't absolutely necessary)
```
mkdir target-root && cd target-root && wget
https://storage.googleapis.com/testmisc/target-root.tar.gz && tar xzf target-root.tar.gz
```

#### To build:
```
make run no-accel
```

### Documentation

You can find more documentation on the OPS [docs site](https://nanovms.gitbook.io/ops/)

### Benchmarks

In an effort for transparency and to collect, categorize, and document
benchmarks we will start listing them here. The aims should be to be as
reproducible and contain as much information as possible:

[Go on GCloud](https://github.com/nanovms/nanos/wiki/go_gcloud): 18k req/sec

[Rust on GCloud](https://github.com/nanovms/nanos/wiki/rust_gcloud): 22k req/sec

[Node.JS on AWS](https://github.com/nanovms/nanos/wiki/nodejs_aws): 2k req/sec

[Node.JS on GCloud](https://github.com/nanovms/nanos/wiki/nodejs_gcloud): 4k req/sec

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

### Feedback

How are you using Nanos? Take this very short survey and help us grow
the project. It will take just a minute but help us out!

[Feedback Form](https://ian377411.typeform.com/to/nm0soI)

### Who is Using Nanos?

If you are using Nanos for a project at your company or organization
feel free to open up a PR and list your project/company below.

### Getting Help

We run a public mailing list at:

  nanos-users@nanovms.com

for general questions. If you'd like more in-depth help reach out to the
nanovms folks via drift or email engineering.

If you need something done *now* or want immediate attention to an issue
NanoVMs offers [paid support plans](https://nanovms.com/services/subscription).
