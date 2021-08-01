#!/bin/bash

xtensa-esp32-elf-gcc -c test.S -o test.o
xtensa-esp32-elf-objdump -d test.o > test.dmp
xtensa-esp32-elf-objcopy -O binary test.o test.bin
CODE=$(hexdump -v -e '16/1 "_x%02X" "\n"' test.bin | sed 's/_/\\/g; s/\\x  //g; s/.*/"&"/' | sed 's/\\/\\\\/g')
CODE="s/^#define XTENSA_CODE.+/#define XTENSA_CODE $CODE/"
sed -i -E "$CODE" ../tests/test_xtensa.c