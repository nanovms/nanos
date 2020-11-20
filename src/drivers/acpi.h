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

void init_acpi(kernel_heaps kh);
