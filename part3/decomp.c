#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>

unsigned char *mem;

void sub_dc(uint16_t addr, uint16_t len) {
	write(1, mem + addr, len);
}

void sub_54(uint16_t addr0, uint16_t addr1, uint16_t count) {
	uint16_t r1, r4, r5;
	int i;

	for (i = 0; i < 256; i++) {
		mem[addr0 + i] = i;
	}

	r1 = 0;
	for (i = 0 ; i <= 255; i++) {
		r4 = mem[addr0 + i];
		r1 += r4;

		r4 = i % count;
		r4 = mem[addr1 + r4];
		r1 = (r1 + r4) & 0xff;

		r4 = mem[addr0 + i];
		r5 = mem[addr0 + r1];
		mem[addr0 + i] = r5;
		mem[addr0 + r1] = r4;
	}
}

void sub_9c(uint16_t addr0, uint16_t addr1, uint16_t count) {
	int i;
	uint16_t r0, r1, r5, r6;

	r1 = 0;
	for (i = 0; i < count; i++) {
		r0 = (i + 1) & 0xff;

		r5 = mem[addr0 + r0];
		r1 = (r1 + r5) & 0xff;

		r5 = mem[addr0 + r0];
		r6 = mem[addr0 + r1];

		mem[addr0 + r0] = r6;
		mem[addr0 + r1] = r5;

		r5 = (r5 + r6) & 0xff;

		r5 = mem[addr0 + r5];
		r6 = mem[addr1 + i];
		mem[addr1 + i] = r6 ^ r5;
	}

}

void sub_e0(uint16_t r0) {
	mem[r0] = 26;
	mem[r0 + 1] = 10;
}


uint16_t sub_228(uint16_t r0) {
	uint16_t r3, r4;

	r3 = mem[r0 + 1];
	r4 = mem[r0];
	r4 = r4 << 8;
	r0 = r3 | r4;
	return r0;
}

/* retourne, à partir de l'adresse r0, l'adresse qui contient la valeur r1 */
uint16_t sub_f8(uint16_t r0, uint16_t r1) {
	uint16_t r4;

loc_fe:
	r4 = mem[r0];
	if (r4 == 0) {
		/* fin de chaîne */
		return 0;
	}
	if (r4 == r1) {
		return r0;
	}
	r0++;
	goto loc_fe;
}

void sub_148(uint16_t r0, uint16_t r1) {
	uint16_t r2, r3, r4;

	r4 = 10000;
	r0--;
loc_158:
	r0++;
	r2 = r1 / r4;
	r3 = r2 * r4;
	r1 = r1 - r3;
	r4 = r4 / 10;

	mem[r0] = 0x20;
	if (r2 == 0) {
		goto loc_158;
	}

	mem[r0] = r2 + 0x30;
	if (r4 != 0)
		goto loc_158;

}

void run(void) {
	uint16_t r0, r10;
	
	sub_dc(0x18c, 0x1b);
	sub_54(0x1000, 0x17c, 0xf);

	sub_9c(0x1000, 0x1b2, 0x29);

	sub_e0(0x1100);
	r10 = sub_228(0x1100);
	r0 = sub_f8(0x1b2, '$');
	sub_148(r0, r10);
	sub_dc(0x1b2, 0x29);
	sub_dc(0x1a8, 9);
}

int main(int argc, char **argv) {
	struct stat st;
	int fd;

	mem = malloc(0xffff);

	stat("fw.bin", &st);
	fd = open("fw.bin", O_RDONLY);
	read(fd, mem, st.st_size);
	close(fd);

	run();
	exit(EXIT_SUCCESS);
}
