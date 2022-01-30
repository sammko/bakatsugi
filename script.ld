MEMORY
{
  page (rwx) : ORIGIN = 0, LENGTH = 4096
}

PHDRS
{
  phdr PT_LOAD;
}

SECTIONS
{
  /DISCARD/ : { *(.comment) }
  .text : { *(.text) } :phdr
  .rodata : { *(.rodata.*) } :phdr
  .data : { *(.data) } :phdr
  .bss  : { *(.bss)  } :phdr
}
