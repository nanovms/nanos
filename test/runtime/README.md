# Examples

Set ```TARGET``` to run a specific example:
```
make TARGET=<example> run
```

Certain examples require ```go``` to be built. 

More examples can be found in [docs/examples#examples](https://docs.opsity/ops/examples#examples).

Example | Language | Description
-|-|-
aio | c | 
aslr | c | 
creat | c | 
dup | c | 
epoll | c | 
eventfd | c | 
fadvise | c | 
fallocate | c | 
fcntl | c | 
fst | go | 
fs_full | c | 
ftrace | c | 
futex | c | 
futexrobust | c | 
getdents | c | 
getrandom | c | 
hw | c | hello world (dynamic linking)
hws | c | hello world (static linking)
hwg | go | hello world
inotify | c | 
io_uring | c | 
ktest | c | 
mkdir | c | 
mmap | c | 
netlink | c | 
netsock | c | 
nullpage | c | 
paging | c | 
pipe | c | 
readv | c | 
rename | c | 
sandbox | c | 
sendfile | c | 
shmem | c | 
signal | c | 
sigoverflow | c | 
socketpair | c | 
symlink | c | 
syslog | c | 
thread_test | c | 
time | c | 
tlbshootdown | c | 
tun | c | 
udploop | c | 
umcg | c | 
unixsocket | c | 
unlink | c | 
vsyscall | c | 
web | c | webserver on localhost:8080 (dynamic linking)
webs | c | webserver on localhost:8080 (static linking)
webg | go | webserver on localhost:8080
write | c | 
writev | c |
