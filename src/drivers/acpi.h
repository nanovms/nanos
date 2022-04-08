#define ACPI_PM1_STS   0x00
#define ACPI_PM1_EN     0x02
#define ACPI_PM1_CNT    0x04

/* PM1_STS */
#define ACPI_PM1_PWRBTN_STS (1 << 8)

/* PM1_EN */
#define ACPI_PM1_PWRBTN_EN  (1 << 8)

/* PM1_CNT */
#define ACPI_PM1_SLP_EN         (1 << 13)
#define ACPI_PM1_SLP_TYP(typ)   (typ << 10)
#define ACPI_PM1_SCI_EN         (1 << 0)

#define ACPI_SCI_IRQ    9

/* MADT controller types */
#define ACPI_MADT_LAPIC     0
#define ACPI_MADT_IOAPIC    1
#define ACPI_MADT_LAPICx2   9
#define ACPI_MADT_GEN_INT   11
#define ACPI_MADT_GEN_DIST  12
#define ACPI_MADT_GEN_RDIST 14
#define ACPI_MADT_GEN_TRANS 15

#define MADT_LAPIC_ENABLED  1
/* ACPI table structures */
typedef struct acpi_rsdp {
    u8 sig[8];
    u8 checksum;
    u8 oem_id[6];
    u8 rev;
    u32 rsdt_addr;
    u32 length;
    u64 xsdt_addr;
    u8 ext_checksum;
    u8 res[3];
} __attribute__((packed)) *acpi_rsdp;

typedef struct acpi_header {
    u8 sig[4];
    u32 length;
    u8 rev;
    u8 checksum;
    u8 oem_id[6];
    u8 oem_table_id[8];
    u32 oem_rev;
    u8 creator_id[4];
    u8 creator_rev[4];
} __attribute__((packed)) *acpi_header;

typedef struct acpi_rsdt {
    struct acpi_header h;
} __attribute__((packed)) *acpi_rsdt;

typedef struct acpi_madt {
    struct acpi_header h;
    u32 lapic_addr;
    u32 flags;
} __attribute__((packed)) *acpi_madt;

typedef struct acpi_lapic {
    u8 type;
    u8 length;
    u8 uid;
    u8 id;
    u32 flags;
} __attribute__((packed)) *acpi_lapic;

typedef struct acpi_lapic_x2 {
    u8 type;
    u8 length;
    u8 res[2];
    u32 id;
    u32 flags;
    u32 uid;
} __attribute__((packed)) *acpi_lapic_x2;

typedef struct acpi_ioapic {
    u8 type;
    u8 length;
    u8 id;
    u8 res;
    u32 addr;
    u32 gsi_base;
} __attribute__((packed)) *acpi_ioapic;

typedef struct acpi_gen_int
{
    u8 type;
    u8 length;
    u16 res;
    u32 cpu_iface_num;
    u32 acpi_proc_uid;
    u32 flags;
    u32 parking_proto_ver;
    u32 perf_int_gsiv;
    u64 parked_addr;
    u64 base_addr;
    u64 gicv_base_addr;
    u64 gich_base_addr;
    u32 vgic_int;
    u64 gicr_base_addr;
    u64 mpidr;
    u8 efficiency_class;
    u8 res2;
    u16 spe_int;

} __attribute__((packed)) *acpi_gen_int;

/* acpi_gen_int flags */
#define MADT_GENINT_ENABLED U64_FROM_BIT(0)

typedef struct acpi_gen_dist {  /* Generic Distributor */
    u8 type;
    u8 length;
    u16 res;
    u32 gic_id;
    u64 base_address;
    u32 global_irq_base;
    u8 version;
    u8 res2[3];
} __attribute__((packed)) *acpi_gen_dist;

typedef struct acpi_gen_redist {    /* Generic Redistributor */
    u8 type;
    u8 length;
    u16 res;
    u64 base_address;
    u32 len;
} __attribute__((packed)) *acpi_gen_redist;

typedef struct acpi_gen_trans { /* Generic Translator */
    u8 type;
    u8 length;
    u16 res;
    u32 translation_id;
    u64 base_address;
    u32 res2;
} __attribute__((packed)) *acpi_gen_trans;

static inline boolean acpi_checksum(void *a, u8 len)
{
    u8 *addr = a;
    u8 sum = 0;
    while (len--)
        sum += *addr++;
    return sum == 0;
}

typedef closure_type(madt_handler, void, u8, void *);
typedef closure_type(mcfg_handler, boolean, u64, u16, u8, u8);
typedef closure_type(spcr_handler, void, u8, u64);

void init_acpi(kernel_heaps kh);
void init_acpi_tables(kernel_heaps kh);
boolean acpi_walk_madt(madt_handler mh);
boolean acpi_walk_mcfg(mcfg_handler mh);
boolean acpi_parse_spcr(spcr_handler h);
