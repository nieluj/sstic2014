CFLAGS=-Wall -pedantic -Iinclude

decrypt-data: decrypt-data.c chacha.c
	gcc $(CFLAGS) -o decrypt-data decrypt-data.c chacha.c

crackme: crackme.c
	gcc $(CFLAGS) -o crackme crackme.c

unpack: unpack.c
	gcc $(CFLAGS) -o unpack unpack.c

badbios-embedded.bin: badbios.bin unpack
	./unpack badbios.bin badbios-embedded.bin

cipher.bin: badbios-embedded.bin
	dd if=badbios-embedded.bin of=cipher.bin bs=1 skip=12288 count=65536

cleartext.bin: decrypt-data cipher.bin
	./decrypt-data cipher.bin cleartext.bin

vm.asm: cleartext.bin
	ruby disassvm.rb cleartext.bin > vm.asm

payload.bin: badbios-embedded.bin
	echo 0BADB10515DEAD11 | qemu-aarch64 badbios-embedded.bin

badbios.bin.objdump: badbios.bin
	/usr/bin/aarch64-linux-gnu-objdump -d badbios.bin > badbios.bin.objdump

badbios-embedded.bin.objdump: badbios.bin
	/usr/bin/aarch64-linux-gnu-objdump -d badbios-embedded.bin > badbios-embedded.bin.objdump

badbios-vm: badbios-vm.c chacha.c
	gcc $(CFLAGS) -o badbios-vm badbios-vm.c chacha.c

all: decrypt-data crackme unpack badbios-embedded.bin payload.bin cleartext.bin vm.asm cipher.bin \
    badbios-vm badbios.bin.objdump badbios-embedded.bin.objdump

clean:
	rm -f decrypt-data crackme unpack badbios-embedded.bin payload.bin cleartext.bin vm.asm cipher.bin \
		badbios.bin.objdump badbios-embedded.bin.objdump
