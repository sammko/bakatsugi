MEMORY
{
  page (rwx) : ORIGIN = 0, LENGTH = 4096
}

SECTIONS
{
  .text : { *(.text) } >page
  .data : { *(.data) } >page
  .bss  : { *(.bss)  } >page
}
