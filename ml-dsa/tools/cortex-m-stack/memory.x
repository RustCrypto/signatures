/* QEMU mps2-an505 secure code and SRAM aliases. */
MEMORY {
  FLASH : ORIGIN = 0x10000000, LENGTH = 512K
  RAM : ORIGIN = 0x38000000, LENGTH = 2M
}
