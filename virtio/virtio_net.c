

void vtnet_transmit(void *base, int length)
{
}

vtnet_get_hwaddr(struct vtnet_softc *sc)
{
    device_t dev;
    int i;

    dev = sc->vtnet_dev;

    if ((sc->vtnet_flags & VTNET_FLAG_MAC) == 0) {
        /*
         * Generate a random locally administered unicast address.
         *
         * It would be nice to generate the same MAC address across
         * reboots, but it seems all the hosts currently available
         * support the MAC feature, so this isn't too important.
         */
        sc->vtnet_hwaddr[0] = 0xB2;
        arc4rand(&sc->vtnet_hwaddr[1], ETHER_ADDR_LEN - 1, 0);
        vtnet_set_hwaddr(sc);
        return;
    }

    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        sc->vtnet_hwaddr[i] = virtio_read_dev_config_1(dev,
                                                       offsetof(struct virtio_net_config, mac) + i);
    }
}

