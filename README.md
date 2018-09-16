# uniboot

[![CircleCI](https://circleci.com/gh/deferpanic/uniboot.svg?style=svg)](https://circleci.com/gh/deferpanic/uniboot)

setting up qemu networking

  first setup your bridge environment:
  
```
# create bridge named br0.
ip link add br0 type bridge
# bring up the bridge.
ip link set br0 up
# add the ethernet adapter eth0 to bridge.
ip link set $(ETH0) master br0
# create a tap device named tap0.
ip tuntap add tap0 mode tap user `whoami`
# bring up the bridge.
ip link set tap0 up
# add tap0 to bridge.
ip link set tap0 master br0
# assign ip to bridge.
dhclient -v br0
```

invoke qemu:
```
  -device virtio-net,netdev=n0,mac=[tapeth]  -netdev tap,ifname=tap0,id=n0,script=no
```

the learning bridge should be happy to deal with any random mac, but it really only
works if the guest mac matches the host-assigned tap0 mac

to address the tap0 cdev, need to run as root, have to figure that out

this could all be wrapped up in make or a script or a c program, but its
pretty involved



