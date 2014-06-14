#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <ctype.h>

#ifndef HEXDUMP_COLS
#define HEXDUMP_COLS 8
#endif

void hexdump(void *mem, unsigned int len)
{
	unsigned int i, j;

	for(i = 0; i < len + ((len % HEXDUMP_COLS) ? (HEXDUMP_COLS - len % HEXDUMP_COLS) : 0); i++) {
		/* print offset */
		if(i % HEXDUMP_COLS == 0) {
			printf("0x%06x: ", i);
		}

		/* print hex data */
		if(i < len) {
			printf("%02x ", 0xFF & ((char*)mem)[i]);
		} else { /* end of block, just aligning for ASCII dump */
			printf("   ");
		}

		/* print ASCII dump */
		if(i % HEXDUMP_COLS == (HEXDUMP_COLS - 1)) {
			for(j = i - (HEXDUMP_COLS - 1); j <= i; j++) {
				if(j >= len) { /* end of block, not really printing */
					putchar(' ');
				} else if(isprint(((char*)mem)[j])) { /* printable char */
					putchar(0xFF & ((char*)mem)[j]);        
				} else { /* other char */
					putchar('.');
				}
			}
			putchar('\n');
		}
	}
}

char *mem;

uint32_t parity(uint32_t x) {
	x = x ^ (x >> 1);
	x = (x ^ (x >> 2)) & 0x11111111;
	x = x * 0x11111111;
	return (x >> 28) & 1;
}

void reverse_lfsr(uint32_t r10_1, uint32_t r11_1, uint32_t *r10_0, uint32_t *r11_0) {
	uint32_t r9;
	*r10_0 = (r10_1 << 1) | (r11_1 >> 31);
	r9 = (r10_1 >> 31);
	*r11_0 = (r11_1 << 1);

	if (parity( (*r10_0 & 0xb0000000) ^ (1)) == r9) {
		*r11_0 |= 1;
	}
}

void bla(uint32_t r10, uint32_t r11) {
    int i;
    uint32_t tmp0, tmp1;
    
    for (i = (8184 * 8) ; i >= 0; i--) {
	reverse_lfsr(r10, r11, &tmp0, &tmp1);
	r10 = tmp0;
	r11 = tmp1;
	printf("[%u] r10 = %x, r11 = %x\n", i, r10, r11);
    }
}

int decrypt(uint32_t k0, uint32_t k1) {
	uint32_t r1, r3, r4, r6, r7, r8, r9, r10, r11, r12, r13;
	uint32_t tmp_r10, tmp_r11;
	uint8_t b0, b1;
	int i, j;

	r10 = k0; r11 = k1;
	for (i = 0; i < 8192; i++) {
		r4 = 0;
		//printf("r10 = %x, r11 = %x\n", r10, r11);
		for (j = 0; j < 8; j++) {
			r9 = parity( (r10 & 0xb0000000) ^ (r11 & 1) );
			//printf("r9 = %x\n", r9);
			r11 = (r11 >> 1) | ( (r10 & 1) << 31 );
			r10 = (r10 >> 1) | (r9 << 31);
			//printf("r11 = %x\n", r11);
			printf("r10 = 0x%x, r11 = 0x%x\n", r10, r11);

			r4 |= (r11 & 1 ) << (7 - j) ;
			printf("r4 = %x\n", r4);

			//printf("r10 = %x\n", r10);

			reverse_lfsr(r10, r11, &tmp_r10, &tmp_r11);
			//printf("tmp_r10 = 0x%x, tmp_r11 = 0x%x\n", tmp_r10, tmp_r11);
		}

		b0 = mem[32768 + i];
		printf("[486] mem[%d] : b0 = 0x%x ^ r4 = 0x%x => 0x%x\n", i, b0, r4, b0 ^ r4);
		mem[32768 + i] ^= r4;
	}
	r13 = 32768;
	r12 = 8192;
	r11 = 128;
	r10 = 0;
	r9 = 8;
loc_550:
	r10++;
	r12--;
	if ( (int32_t) r12 <= 0) {
		printf("[0] Invalid padding\n");
		//exit(EXIT_FAILURE);
	}
	r10 = r13 + r12;
	r1 = mem[r10] & 0xff;
	printf("r1 = %x, r12 = %d\n", r1, r12);
	if (r1 == 0)
		goto loc_550;
	r1 = r1 - 128;
	if (r1 != 0) {
		printf("[1] Invalid padding\n");
		//exit(EXIT_FAILURE);
	}
	r10 -= 8;
	if ( (int32_t) r10 <= 0) {
		printf("[2] Invalid padding\n");
		//exit(EXIT_FAILURE);
	}
	printf("gagné !\n");
}

int main(int argc, char **argv) {
	int i, fd;
	struct stat st;
	char *input;

	if (argc == 1) {
		//bla(0xe34a7499, 0x938af9e9);
//		bla(0x960ed9a3, 0xacec7ca3);
		bla(0x40caf153, 0xc32a6d56);
		exit(EXIT_SUCCESS);
	}
	
	if (argc != 2) {
		fprintf(stderr, "usage: %s cleartext\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	input = argv[1];
	if (stat(input, &st) == -1) {
		perror("stat");
		exit(EXIT_FAILURE);
	}

	fd = open(input, O_RDONLY);
	if (fd == -1) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	mem = malloc(st.st_size);

	for (i = 0; i < (st.st_size/1024); i++) {
		read(fd, mem + 1024 * i, 1024);
	}
	close(fd);

	//hexdump(mem, st.st_size);
	//decrypt(0xa3a2a1a0, 0xa7a6a5a4);
	//decrypt(0xaaaaaaaa, 0xbbbbbbbb);
	//decrypt(0x68334eb3, 0x11afe54f);
	decrypt(0x5b1ad0b, 0x11adde15);
	// key is 0BADB10515DEAD11

	//hexdump(mem + 32768, 8192);

	fd = open("out.bin", O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP);
	write(fd, mem + 32768, 8192);
	close(fd);

}
