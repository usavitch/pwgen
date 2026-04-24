#!/bin/bash

[ $# -eq 0 ] && echo "Usage: $0 file.asm" && exit 1; nasm -f elf64 "$1" -o "${1%.*}.o" && ld -s --strip-all -z noseparate-code -z max-page-size=0x1000 "${1%.*}.o" -o "${1%.*}" && strip -s "${1%.*}" 2>/dev/null; rm -f "${1%.*}.o"; echo "Binary size: $(wc -c < "${1%.*}") bytes" || echo "Failed"
