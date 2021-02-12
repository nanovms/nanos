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

/* ACPI table signatures */
#define ACPI_SIG_MADT   0x43495041  // "APIC"

/* MADT controller types */
#define ACPI_MADT_LAPIC     0
#define ACPI_MADT_IOAPIC    1
#define ACPI_MADT_LAPICx2   9

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

static inline boolean acpi_checksum(void *a, u8 len)
{
    u8 *addr = a;
    u8 sum = 0;
    while (len--)
        sum += *addr++;
    return sum == 0;
}

typedef closure_type(madt_handler, void, u8, void *);

void init_acpi(kernel_heaps kh);
void *acpi_get_table(u32 sig);
void acpi_walk_madt(acpi_madt madt, madt_handler mh);
