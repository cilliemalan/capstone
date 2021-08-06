#!/bin/bash

# this script compiles the test assembly for xtensa and
# produces a flat binary. The toolchain is assumed to
# be in path.
#
# The linux toolchain can be found at (also works on WSL)
# https://dl.espressif.com/dl/xtensa-esp32-elf-linux64-1.22.0-80-g6c4433a-5.2.0.tar.gz
# Windows (you will also need MSYS2)
# https://dl.espressif.com/dl/xtensa-esp32-elf-win32-1.22.0-61-gab8375a-5.2.0.zip
# Mac OS
# https://dl.espressif.com/dl/xtensa-esp32-elf-osx-1.22.0-61-gab8375a-5.2.0.tar.gz

xtensa-esp32-elf-gcc -c test.S -o test.o
xtensa-esp32-elf-objdump -d test.o > test.dmp
xtensa-esp32-elf-objcopy -O binary test.o test.bin
CODE=$(hexdump -v -e '16/1 "_x%02X" "\n"' test.bin | sed -E ':a;N;$!ba;s/\n//g; s/_/\\/g; s/\\x  //g; s/.*/"&"/g' | sed 's/\\/\\\\/g')
CODE="s/^#define XTENSA_CODE.+/#define XTENSA_CODE $CODE/"
sed -i -E "$CODE" ../test_xtensa.c
