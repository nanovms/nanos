# uniboot

[![CircleCI](https://circleci.com/gh/deferpanic/uniboot.svg?style=svg)](https://circleci.com/gh/deferpanic/uniboot)

setting up qemu networking

  first setup your bridge environment:
  
    brctl addbr foo                         create the bridge
    find your external interface [intr]     note the address/mask assigned to [intr], call it [intraddr]
    
    ip addr flush dev [intr]                remove its ip address!
    ifconfig foo [intraddr]                   
    brctl addif [intr]                      if you do these three lines as a batch, you can keep connectivity
    
    tunctl                                  set tap0 to persistent - this helps
                                            note the ethernet address of tap0 [tapeth]
    brctl addif foo tap0

    ip link set [intr] promisc on           accept packets for the guest ether
    route add default gw [gateway]                     
    
note - i have been 'brctl setfd 0' - its not supposed to be necessary in non-stp environments

invoke qemu:
```
  -device virtio-net,netdev=n0,mac=[tapeth]  -netdev tap,ifname=tap0,id=n0,script=no
```

the learning bridge should be happy to deal with any random mac, but it really only
works if the guest mac matches the host-assigned tap0 mac

to address the tap0 cdev, need to run as root, have to figure that out

this could all be wrapped up in make or a script or a c program, but its
pretty involved



