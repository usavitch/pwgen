#!/bin/bash
# compile.sh - сборка генератора паролей

set -e

echo "=== Сборка SHA-512 модуля ==="
#nasm -f elf64 sha512.asm -o sha512.o

echo "=== Сборка основного генератора ==="
nasm -f elf64 c22.asm -o c22.o

echo "=== Линковка ==="
ld  c22.o -o c22

echo "=== Готово ==="
echo "Размер бинарного файла: $(stat -c%s c22) байт"
echo "Запуск: ./c22"
