
/*
 * I/O port read/write wrappers.
 */
#define vtpci_read_config_1(sc, o)      bus_read_1((sc)->vtpci_res, (o))
#define vtpci_read_config_2(sc, o)      bus_read_2((sc)->vtpci_res, (o))
#define vtpci_read_config_4(sc, o)      bus_read_4((sc)->vtpci_res, (o))
#define vtpci_write_config_1(sc, o, v)  bus_write_1((sc)->vtpci_res, (o), (v))
#define vtpci_write_config_2(sc, o, v)  bus_write_2((sc)->vtpci_res, (o), (v))
#define vtpci_write_config_4(sc, o, v)  bus_write_4((sc)->vtpci_res, (o), (v))

void vtpci_read_dev_config(device_t dev, bus_size_t offset,
                           void *dst, int length)
{
    struct vtpci_softc *sc;
    bus_size_t off;
    uint8_t *d;
    int size;

    sc = device_get_softc(dev);
    off = VIRTIO_PCI_CONFIG(sc) + offset;

    for (d = dst; length > 0; d += size, off += size, length -= size) {
        if (length >= 4) {
            size = 4;
            *(uint32_t *)d = vtpci_read_config_4(sc, off);
        } else if (length >= 2) {
            size = 2;
            *(uint16_t *)d = vtpci_read_config_2(sc, off);
        } else {
            size = 1;
            *d = vtpci_read_config_1(sc, off);
        }
    }
}
