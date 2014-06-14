#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <elf.h>
#include <ctype.h>

#include "ecrypt-sync.h"

#define BLK_UNUSED (1 << 1)

typedef struct {
	u64 addr;
	u64 idx;
	u64 flags;
} block_info_st;

typedef void (*vm_ptr_t)(char *, uint32_t);
typedef struct {
	vm_ptr_t fptr;
	char *name;
} func_info_st;
func_info_st func_infos[31];

block_info_st *block_infos;
block_info_st mmu[32];
ECRYPT_ctx ctx;
u64 a, b, c;

char *badbios;
char *mem_new_prog;
char *cipher;
char *output;
char *mem_data;

char *addr0;
char *addr1;
char *addr2;

uint8_t b0;
uint32_t w4;
uint64_t dw8;

uint32_t write_data(char *addr, uint32_t offset, char *src, uint32_t count);
uint32_t read_data(char *addr, uint32_t offset, char *dest, uint32_t count);
void sub_402660(char *addr, uint32_t arg1, uint32_t arg2);
uint32_t sub_4025f4(char *addr, uint32_t arg);
int decode_ins(char *addr);

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


void do_init(void) {
	int i;
	void *tmp;
	/* -> segfault
	memset(block_infos, 0, 32 * sizeof(block_info_st));
	for (i=0 ; i<32; i++) {
		block_infos[i].flags = BLK_UNUSED ;
	}
	*/

	tmp = mmap((void *) 0x500000, 69632, PROT_READ|PROT_WRITE,
			MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, 0, 0);
	if (tmp == (void *) -1) {
		perror("error during mmap");
		exit(EXIT_FAILURE);
	}
	output = (char *) tmp;
	printf("output = %p\n", output);
	
	tmp = mmap((void *) 0x4000802000, 65536, PROT_READ|PROT_WRITE,
			MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, 0, 0);
	if (tmp == (void *) -1) {
		perror("error during mmap");
		exit(EXIT_FAILURE);
	}
	cipher = (char *) tmp;
	printf("cipher = %p\n", cipher);


}

Elf64_Shdr *find_shdr(char *sname, char *badbios) {
	Elf64_Ehdr *elf_hdr;
	Elf64_Shdr *shdr;
	Elf64_Shdr *str_shdr;
	char *sname_table;
	int i;

	elf_hdr = (Elf64_Ehdr *) badbios;
        str_shdr = (Elf64_Shdr *) (badbios + elf_hdr->e_shoff +
        		elf_hdr->e_shstrndx * elf_hdr->e_shentsize);
        sname_table = badbios + str_shdr->sh_offset;

        for (i = 0; i < elf_hdr->e_shnum; i++) {
        	shdr = (Elf64_Shdr *) (badbios + elf_hdr->e_shoff + i * elf_hdr->e_shentsize);
        	if (!strcmp(sname,  sname_table + shdr->sh_name)) {
        		return shdr;
		}
	}
	return NULL;
}

void dump_elf_sections(char *badbios) {
	Elf64_Ehdr *elf_hdr;
	Elf64_Shdr *section_hdr;
	Elf64_Shdr *str_section_hdr;
	char *section_name_table;
	int i;

	elf_hdr = (Elf64_Ehdr *) badbios;
	printf("Section header table file offset: 0x%lx\n", elf_hdr->e_shoff);
	printf("Section header table entry count: 0x%x\n", elf_hdr->e_shnum);
        printf("Section header string table index: 0x%x\n", elf_hdr->e_shstrndx);

        str_section_hdr = (Elf64_Shdr *) (badbios + elf_hdr->e_shoff +
        		elf_hdr->e_shstrndx * elf_hdr->e_shentsize);
        section_name_table = badbios + str_section_hdr->sh_offset;

	for (i = 0; i < elf_hdr->e_shnum; i++) {
		section_hdr = (Elf64_Shdr *) (badbios + elf_hdr->e_shoff + i * elf_hdr->e_shentsize);
		printf("Section name: %s\n", section_name_table + section_hdr->sh_name);
		printf("section type: %x\n", section_hdr->sh_type);
	}
}

#define REMAP_VADDR(shdr, base, vaddr) (base + ((uint64_t) vaddr - shdr->sh_addr))

/* sub_10304 */
uint32_t load_new_prog(void *src_addr, void *dst_addr, uint32_t src_len, uint32_t dst_len) {
	FILE *f;
	char *x0, *x1, *x2, *x3, *x4, *x5, *x6, *x7, *x8, *x9, *x10, *x11, *x12, *x19;
	uint8_t b2, b4, b6, b8;
	uint32_t w0, w3, w8;
	uint64_t u0, u2, u4, u6, u5, u7, u8, u17, u18;
	uint64_t array[8] = { 4, 1, 2, 1, 4, 4, 4, 4 };
	uint64_t array_2[8] = { 0, 0, 0, 0xFFFFFFFFFFFFFFFF, 0, 1, 2, 3 };

	printf("src = %p, dst = %p\n", src_addr, dst_addr);

	w0 = 0;
	x0 = src_addr;
	x1 = dst_addr;
	x2 = dst_addr; // X2
	x6 = src_addr; // X3

	x12 = x2 + dst_len;
	x9 = x12 - 0xc;

	x7 = x6 + src_len;
	x10 = x7 - 8;
	x11 = x7 - 6;

	printf("x9 = %p, x10 = %p\n", x9, x10);

loc_1036c:
	b8 = *x6;
	x3 = x6 + 1;
	u4 = b4 = b8 >> 4;

	if (b4 == 0xF)
		goto loc_10418;
loc_10380:
	printf("\n-> loc_10380, u4 = %x, x2 = %p, x3 = %p\n", u4, x2, x3);
	x5 = x2 + u4;
	x6 = x3 + u4;
	if (x5 > x9)
		goto loc_1044c;
loc_10390:
	printf("-> loc_10390\n");
	if (x6 > x10)
		goto loc_1044c;
loc_10398:
	printf("-> loc_10398: x2 = %p, x3 = %p, x5 = %p\n", x2, x3, x5);
	u4 = *( (uint64_t *) x3);
	x3 += 8;

	printf("write %p : %16.16lx\n", x2, u4);
	*( (uint64_t *) x2) = u4;
	x2 += 8;

	if (x5 > x2)
		goto loc_10398;

	b2 = x2 - x5;
	printf("b2 = %d\n", b2);
	x6 = x3 - b2;
	printf("x6 = %p\n", x6);

	u4 = *((uint16_t *) x6);
	x6 += 2;
	printf("u4 = %lx\n", u4);
	x4 = x5 - u4;
	printf("x4 = %p\n", x4);
	if ((char *) dst_addr > x4)
		goto loc_10570;

	u2 = b2 = b8 & 0xF;
	if (b2 == 0xF)
		goto loc_10468;
loc_103cc:
	printf("-> loc_103cc: x4 = %p, x5 = %p\n", x4, x5);
	u8 = x5 - x4;
	if (u8 <= 7)
		goto loc_104fc;
	u8 = *( (uint64_t *) x4);
	x4 += 8;
	x3 = x5;
	printf("write %p : %16.16lx\n", x3, u8);
	*( (uint64_t *) x3) = u8;
	x3 += 8;

loc_103E4:
	printf("-> loc_103E4, u2 = %x, x3 = %p\n", u2, x3);
	x2 = x3 + u2 - 4;
	if (x9 < x2)
		goto loc_104c4;
loc_103F4:
	printf("-> loc_103F4, x2 = %p, x3 = %p, x4 = %p, x6 = %p\n", x2, x3, x4, x6);
	u5 = *((uint64_t *) x4);
	x4 += 8;
	printf("write %p : %16.16lx\n", x3, u5);
	*((uint64_t *) x3) = u5;
	x3 += 8;
	if (x2 > x3)
		goto loc_103F4;
	b8 = *((uint8_t *) x6);
	printf("b8 = %x\n", b8);

	x3 = x6 + 1;
	u4 = b4 = b8 >> 4;
	printf("b4 = %x\n", b4);
	if (b4 != 0xF)
		goto loc_10380;

loc_10418:
	printf("-> loc_10418: x3 = %p, x7 = %p\n", x3, x7);
	if (x7 > x3)
		goto loc_1042c;
	goto loc_10380;
loc_10424:
	printf("-> loc_10424\n");
	if (b6 != 0xFF)
		goto loc_10380;
loc_1042c:
	printf("-> loc_1042c: x3 = %p, u4 = %x\n", x3, u4);

	b6 = *((uint8_t *) x3);
	x3 += 1;
	u4 += b6;
	if (x3 != x7)
		goto loc_10424;
	x5 = x2 + u4;
	x6 = x3 + u4;
	if (x5 < x9)
		goto loc_10390;
loc_1044c:
	printf("-> loc_1044c : x6 = %p, x7 = %p\n", x6, x7);
	if (x7 == x6)
		goto loc_10484;
loc_10454:
	printf("-> loc_10454 : code me!\n");
	goto end;
loc_10468:
	printf("-> loc_10468 : x6 = %p, x11 = %p\n", x6, x11);
	if (x6 >= x11)
		goto loc_103cc;
	b8 = *((uint8_t *) x6);
	x6 += 1;
	u2 += b8;
	if (b8 != 0xFF)
		goto loc_103cc;
	goto loc_10468;
loc_10484:
	printf("-> loc_10484 : u4 = %x, x5 = %p, x12 = %p\n", u4, x5, x12);
	if (x12 < x5)
		goto loc_10454;
	if (u4 == 0)
		goto loc_104bc;
	u4 += 1;
	u6 = 1;
	u0 = 0;
	goto loc_104a8;
loc_104a0:
	printf("-> loc_104a0:\n");
	u0 = u6;
	u6 = u7;
loc_104a8:
	printf("-> loc_104a8:\n");
	b8 = *((uint8_t *) (x3 + u0));
	printf("write %p : %2.2x\n", x2 + u0, b8);
	u7 = u6 + 1;
	*((uint8_t *) (x2 + u0)) = b8;
	if (u7 != u4)
		goto loc_104a0;
loc_104bc:
	printf("-> loc_104bc\n");
	hexdump(dst_addr, 512);
	f = fopen("badbios-embedded.bin", "w");
	fwrite(dst_addr, 1, 0x2c07, f);
	fclose(f);
	printf("x5 = %p\n", x5);
	printf("x1 = %p\n", x1);

	w0 = x5 - x1;
	goto end;
loc_104c4:
	printf("-> loc_104c4 : code me!\n");
	goto end;
loc_104fc:
	printf("-> loc_104fc\n");
	w3 = *((uint8_t *) x4);

	printf("write %p : %2.2x\n", x5, w3);
	*((uint8_t *) x5) = w3;

	w3 = *((uint8_t *) (x4 + 1));

	u17 = array[u8];

	printf("write %p : %2.2x\n", x5 + 1, w3);
	*((uint8_t *) (x5 + 1)) = w3;

	w3 = *((uint8_t *) (x4 + 2));
	u18 = array_2[u8];

	printf("write %p : %2.2x\n", x5 + 2, w3);
	*((uint8_t *) (x5 + 2)) = w3;

	w8 = *((uint8_t *) (x4 + 3));
	x19 = x4 + u17;

	printf("write %p : %2.2x\n", x5 + 3, w8);
	*((uint8_t *) (x5 + 3)) = w8;

	w8 = *((uint32_t *) (x4 + u17));
	x3 = x5 + 8;
	x4 = x19 - u18;

	printf("write %p : %8.8x, u17 = %lx\n", x5 + 4, w8, u17);
	*((uint32_t *) (x5 + 4)) = w8;

	goto loc_103E4;

loc_10570:
	printf("-> loc_10570: x6 = %p\n", x6);
	x3 = x6;
	goto loc_10454;
end:
	return w0;

}

/* affiche une chaîne de caractères */
void sub_401270(char *addr) {
    uint32_t w0, w1, w21, w22, ret;
    uint64_t u3, u7, u20;
    char *x19, *x20;
    uint8_t *p;
    void *tmp;
    printf("-> sub_401270(addr = %p)\n", addr);

    w1 = 2;
    x19 = addr;

    /* supposé retourner un entier signé ? */
    w22 = sub_4025f4(addr, 2);
    w21 = sub_4025f4(addr, 4);

    if (w21 == 0) {
        p = (uint8_t *) addr;
        *p &= 0xFFFFFFFE;
	*((uint32_t *) (addr + 4)) = 5;
	return;
    }

    tmp = mmap((void *) 0x4000813000, 4096, PROT_READ|PROT_WRITE,
            MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, 0,0);
    if ((tmp == (void *) -1) || (tmp == NULL)) {
        printf("code me ! loc_40146C\n");
        exit(EXIT_FAILURE);
    }
    x20 = tmp;

    w1 = sub_4025f4(addr, 3);

    w0 = read_data(addr, w1, x20, w21);

    u3 = w22;

//    ret = write(u3, x20, w21);
    ret = write(2, x20, w21);

    sub_402660(addr, 1, ret);
    u20 = munmap(x20, w21);
}

void sub_400e08(char *addr) {
    uint32_t w1, w2, w3, w22, w19, w21;
    char *x20, *x21;
    uint8_t *p;
    void *tmp;

    x20 = addr;

    w22 = sub_4025f4(addr, 2); /* fd */
    w19 = sub_4025f4(addr, 4); /* longueur à lire */

    if (w19 == 0) {
        p = (uint8_t *) addr;
        *p &= 0xFFFFFFFE;
	*((uint32_t *) (addr + 4)) = 5;
	return;
    }

    tmp = mmap((void *) 0x4000814000, 4096, PROT_READ|PROT_WRITE,
            MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, 0,0);
    if ((tmp == (void *) -1) || (tmp == NULL)) {
        printf("code me ! loc_40055c\n");
        exit(EXIT_FAILURE);
    }
    x21 = tmp;

    w3 = read(w22, x21, w19);
    sub_402660(addr, 1, w3);

    w1 = sub_4025f4(addr, 3); /* offset de destination */
    w2 = write_data(addr, w1, x21, w19);
    if (w2 != w19) {
    	printf("code me ! loc_400f86\n");
    	exit(EXIT_FAILURE);
    }
    w21 = munmap(x21, w2);
}

/* stocke dans un registre */
void sub_402660(char *addr, uint32_t arg1, uint32_t arg2) {
    uint32_t w0, w4, ret;
    uint64_t u1;
    int64_t s1, tmp;
    uint32_t arg_20;

    //printf("-> sub_402660(addr = %p, arg1 = 0x%x, arg2 = 0x%x)\n", addr, arg1, arg2);

    printf("* R%d <- 0x%x (%u)\n", arg1, arg2, arg2);
    w4 = arg2;

    if (arg1 > 0x16) {
	w0 = *((uint8_t *) addr);
	w0 &= 0xFFFFFFFE;
	*((uint8_t *) addr) = w0;
	*((uint32_t *) (addr + 4)) = 4;
	return;
    }

    if (arg1 == 0) {
	return;
    }

    s1 = arg1;
    s1 -= 1;

    /* SBFM X1, X1, #62, #31 */
    tmp = ROTR64(s1, 62) & 0xffffffff;
    if (s1 & (1 << 63)) {
    	s1 = tmp | 0xffffffff00000000;
    } else {
    	s1 = tmp;
    }
    //printf("arg1 = %x, s1 = %x\n", arg1, s1);

    arg_20 = w4;
    ret = write_data(addr, s1, (char *) &arg_20, 4);

    if (ret != 4) {
	w0 = *((uint8_t *) addr);
	w0 &= 0xFFFFFFFE;
	*((uint8_t *) addr) = w0;
	*((uint32_t *) (addr + 4)) = 4;
    }

}

/* charge un registre */
uint32_t sub_4025f4(char *addr, uint32_t arg) {
    uint32_t w0, w1, w2, arg_10, ret;
    int64_t s1, tmp;
    //printf("sub_4025f4(addr = %p, arg = 0x%x)\n", addr, arg);

    w1 = arg;

    if (w1 <= 16) {
	goto loc_402634;
    }

loc_402634:
    w2 = 0;
    if (w1 == 0) {
        return 0;
    }
    s1 = arg;
    s1 -= 1;

    /* SBFM X1, X1, #62, #31 */
    tmp = ROTR64(s1, 62) & 0xffffffff;
    if (s1 & (1 << 63)) {
    	s1 = tmp | 0xffffffff00000000;
    } else {
    	s1 = tmp;
    }
     
    ret = read_data(addr, s1, (char *) &arg_10, 4);

    if (ret != 4) {
	w0 = *((uint8_t *) addr);
	w0 &= 0xFFFFFFFE;
	*((uint8_t *) addr) = w0;
	*((uint32_t *) (addr + 4)) = 4;
	return -1;
    }
    printf("* R%d -> 0x%x (%u)\n", arg, arg_10, arg_10);

    return arg_10;
}

// http://graphics.stanford.edu/~seander/bithacks.html#ParityNaive
// nombre de bits à 1 pair ou impair
void vm_sub_40077c(char *addr, uint32_t arg) {
	uint32_t rd, rn, w0, w1, w2;
	//printf("-> vm_sub_40077c(addr = %p, arg = 0x%x)\n", addr, arg);

	rn = (arg >> 12) & 0xf;
	w0 = sub_4025f4(addr, rn);
	w0 = w0 ^ (w0 >> 1);
	w1 = w0 ^ (w0 >> 2);
	w2 = w1 & 0x11111111;
	w2 = w2 * 0x11111111;

	rd = (arg >> 8) & 0xf;
	w2 = (w2 >> 28) & 1;

	/* w2 vaut surement 0 */
	sub_402660(addr, rd, w2);
}

void vm_sub_4005f4(char *addr, uint32_t arg) {
	//printf("-> vm_sub_4005f4(addr = %p, arg = 0x%x)\n", addr, arg);
}

void vm_sub_4005fc(char *addr, uint32_t arg) {
	printf("-> vm_sub_4005fc : code me !\n");
	exit(EXIT_FAILURE);
}

void vm_sub_400604(char *addr, uint32_t arg) {
	printf("-> vm_sub_400604 : code me !\n");
	exit(EXIT_FAILURE);
}

void vm_sub_4007ec(char *addr, uint32_t arg) {
	printf("-> vm_sub_4007ec : code me !\n");
	exit(EXIT_FAILURE);
}

void vm_sub_400864(char *addr, uint32_t arg) {
	printf("-> vm_sub_400864 : code me !\n");
	exit(EXIT_FAILURE);
}

void vm_sub_4008c4(char *addr, uint32_t arg) {
    uint32_t rd, rn, result;
    //printf("-> vm_sub_4008c4(addr = %p, arg = 0x%x)\n", addr, arg);

    rd = (arg >> 8) & 0xf;
    rn = (arg >> 12) & 0xf;

    result = sub_4025f4(addr, rd) - sub_4025f4(addr, rn);
    sub_402660(addr, rd, result);
}

void vm_sub_400918(char *addr, uint32_t arg) {
    uint32_t rd, rn, result;
    //printf("-> vm_sub_400918(addr = %p, arg = 0x%x)\n", addr, arg);

    rd = (arg >> 8) & 0xf;
    rn = (arg >> 12) & 0xf;

    result = sub_4025f4(addr, rd) + sub_4025f4(addr, rn);
    sub_402660(addr, rd, result);
}

void vm_sub_400978(char *addr, uint32_t arg) {
	printf("-> vm_sub_400978 : code me !\n");
	exit(EXIT_FAILURE);
}

void vm_sub_400a08(char *addr, uint32_t arg) {
	printf("-> vm_sub_400a08 : code me !\n");
	exit(EXIT_FAILURE);
}

void vm_sub_400a8c(char *addr, uint32_t arg) {
	printf("-> vm_sub_400a8c : code me !\n");
	exit(EXIT_FAILURE);
}

void vm_sub_400b04(char *addr, uint32_t arg) {
    uint32_t rd, rn, result;
    //printf("-> vm_sub_400b04(addr = %p, arg = 0x%x)\n", addr, arg);

    rd = (arg >> 8) & 0xf;
    rn = (arg >> 12) & 0xf;

    result = sub_4025f4(addr, rd) >> sub_4025f4(addr, rn);
    sub_402660(addr, rd, result);
}

void vm_sub_400bd0(char *addr, uint32_t arg) {
    uint32_t rd, rn, result;
    //printf("-> vm_sub_400bd0(addr = %p, arg = 0x%x)\n", addr, arg);

    rd = (arg >> 8) & 0xf;
    rn = (arg >> 12) & 0xf;

    result = sub_4025f4(addr, rd) & sub_4025f4(addr, rn);
    sub_402660(addr, rd, result);
}

void vm_sub_400b78(char *addr, uint32_t arg) {
    uint32_t rd, rn, result;
    //printf("-> vm_sub_400b78(addr = %p, arg = 0x%x)\n", addr, arg);

    rd = (arg >> 8) & 0xf;
    rn = (arg >> 12) & 0xf;

    result = sub_4025f4(addr, rd) << sub_4025f4(addr, rn);
    sub_402660(addr, rd, result);
}

void vm_sub_400c20(char *addr, uint32_t arg) {
    uint32_t rd, rn, result;
    //printf("-> vm_sub_400c20(addr = %p, arg = 0x%x)\n", addr, arg);

    rd = (arg >> 8) & 0xf;
    rn = (arg >> 12) & 0xf;

    result = sub_4025f4(addr, rd) | sub_4025f4(addr, rn);
    sub_402660(addr, rd, result);
}

/* XOR entre deux registres */
void vm_sub_400c90(char *addr, uint32_t arg) {
    uint32_t w0, w1, w2, w20, w21, w22;
    //printf("-> vm_sub_400c90(addr = %p, arg = 0x%x)\n", addr, arg);

    w21 = arg;
    w20 = (w21 >> 8) & 0xf;

    w22 = sub_4025f4(addr, w20);
    w1 = (w21 >> 12) & 0xf;
    w0 = sub_4025f4(addr, w1);
    w2 = w0 ^ w22;

    sub_402660(addr, w20, w2);
}

void vm_sub_400ce0(char *addr, uint32_t arg) {
	uint32_t rd, result;
	//printf("-> vm_sub_400ce0(addr = %p, arg = 0x%x)\n", addr, arg);

	rd = arg >> 8 & 0xf;
	result = sub_4025f4(addr, rd) - 1;
	sub_402660(addr, rd, result);
}

void vm_sub_400d24(char *addr, uint32_t arg) {
	uint32_t rd, result;
	//printf("-> vm_sub_400d24(addr = %p, arg = 0x%x)\n", addr, arg);

	rd = arg >> 8 & 0xf;
	result = sub_4025f4(addr, rd) + 1;
	sub_402660(addr, rd, result);
}

void vm_sub_400d58(char *addr, uint32_t arg) {
	printf("-> vm_sub_400d58 : code me !\n");
	exit(EXIT_FAILURE);
}

/* met un registre à 0 */
void vm_sub_400d9c(char *addr, uint32_t arg) {
    uint64_t u1, u2;
    uint32_t w2;

    //printf("-> vm_sub_400d9c(addr = %p, arg = 0x%x)\n", addr, arg);

    u1 = arg;
    /* ubfx x2, x1, 12, 16 */
    /* a priori w2 vaut toujours 0 */
    u2 = (arg >> 12) & 0xffff;
    w2 = u2 << 16;
    /* nibble de poids fort de u1 */
    u1 = (arg >> 8) & 0xf;

    sub_402660(addr, u1, w2);
}

/*
   0x400dac:    stp     x29, x30, [sp,#-48]!
   0x400db0:    mov     x29, sp
   0x400db4:    mov     w2, w1
   0x400db8:    stp     x19, x20, [sp,#16]
   0x400dbc:    ubfx    x19, x2, #8, #4
=> 0x400dc0:    mov     w1, w19
   0x400dc4:    add     sp, sp, #0x10
   0x400dc8:    bic     x28, x28, xzr <-> x28 = x28 & ~0 = x28
   0x400dcc:    add     sp, sp, #0x10
   0x400dd0:    str     x21, [sp]
   0x400dd4:    sub     sp, sp, #0x10
   0x400dd8:    sub     sp, sp, #0x10
   0x400ddc:    ubfx    x20, x2, #12, #16
   0x400de0:    and     x21, x0, x0
   0x400de4:    bl      0x4025f4
   0x400de8:    orr     w2, w0, w20
   0x400dec:    mov     w1, w19
   0x400df0:    and     x0, x21, x21
   0x400df4:    ldp     x19, x20, [sp,#16]
   0x400df8:    ldr     x21, [sp,#32]
   0x400dfc:    ldp     x29, x30, [sp],#48
   0x400e00:    eor     x8, x8, xzr
   0x400e04:    b       0x402660
 */
void vm_sub_400dac(char *addr, uint32_t arg) {
    	uint32_t w1, w2, w19, ret;
    	uint64_t u2, u19, u20;
	//printf("-> vm_sub_400dac(addr = %p, arg = 0x%x)\n", addr, arg);

	w2 = arg;
	u19 = (w2 >> 8) & 0xf;
	w1 = u19;

	u20 = (arg >> 12) & 0xffff;
	ret = sub_4025f4(addr, w1);

	sub_402660(addr, u19, ret | u20);
}

void vm_sub_401030(char *addr, uint32_t arg) {
	printf("-> vm_sub_401030 : code me !\n");
	exit(EXIT_FAILURE);
}

void vm_sub_4010ec(char *addr, uint32_t arg) {
	printf("-> vm_sub_401030 : code me !\n");
	exit(EXIT_FAILURE);
}

void vm_sub_4011b4(char *addr, uint32_t arg) {
    uint32_t rd, rn, w1, w4, w21, var_s0, ret;
    uint8_t *p;
    //printf("-> vm_sub_4011b4(addr = %p, arg = 0x%x)\n", addr, arg);
    rn = (arg >> 12) & 0xf;

    w21 = sub_4025f4(addr, rn);

    rd = (arg >> 8) & 0xf;
    w4 = sub_4025f4(addr, rd) & 0xff;

    w1 = (arg >> 16) & 0xffffffff;

    w1 += w21;

    var_s0 = w4;

    ret = write_data(addr, w1, (char *) &var_s0, 1);
    if (ret != 1) {
	    p = (uint8_t *) addr;
	    *p &= 0xFFFFFFFE;
	    *((uint32_t *) (addr + 4)) = 3;
    }


}

// syscall
void vm_sub_401490(char *addr, uint32_t arg) {
    uint32_t w0, w1;

    //printf("-> vm_sub_401490(addr = %p, arg = 0x%x)\n", addr, arg);

    w1 = 1;
    w0 = sub_4025f4(addr, w1);

    if (w0 == 0) {
    	    printf("code unreachable!\n");
    	    exit(EXIT_FAILURE);
    	    /*
       sub_40060c(addr);
       return;
       */
    }

    if (w0 == 1) {
    	sub_400e08(addr);
    	return;
    }

    if (w0 == 2) {
        sub_401270(addr);
        return;
    }

    if (w0 == 3) {
    	//sub_400708(addr);
        printf("code me ! loc_40153c\n");
        exit(EXIT_FAILURE);
    }
}

void vm_sub_401580(char *addr, uint32_t arg) {
	uint32_t w19, w0, w1, var_s8, arg_10, ret;
	uint8_t *p;
	char *x20;

	//printf("-> vm_sub_401580(addr = %p, arg = 0x%x)\n", addr, arg);
	w19 = arg;
	
	w1 = (w19 >> 12) & 0xf;
	x20 = addr;
	var_s8 = 0;

	w0 = sub_4025f4(addr, w1);
	w1 = (w19 >> 16) & 0xffffffff;
	w1 += w0;

	ret = read_data(addr, w1, (char *) &arg_10, 4);
	if (ret != 4) {
        	p = (uint8_t *) addr;
        	*p &= 0xFFFFFFFE;
		*((uint32_t *) (addr + 4)) = 3;

	}
	w1 = (w19 >> 8) & 0xf;
	sub_402660(addr, w1, arg_10);

}

void vm_sub_401634(char *addr, uint32_t arg) {
	printf("-> vm_sub_401634 : code me !\n");
	exit(EXIT_FAILURE);
}

void vm_sub_4016e4(char *addr, uint32_t arg) {
	uint32_t rd, rn, w1, ret, arg_10 = 0;
	uint8_t *p;
	//printf("-> vm_sub_4016e4(addr = %p, arg = 0x%x)\n", addr, arg);

	rn = (arg >> 12) & 0xf;
	ret = sub_4025f4(addr, rn);

	w1 = (arg >> 16) & 0xffffffff;
	w1 += ret;

	ret = read_data(addr, w1, (char *) &arg_10, 1);
	if (ret != 1) {
        	p = (uint8_t *) addr;
        	*p &= 0xFFFFFFFE;
		*((uint32_t *) (addr + 4)) = 3;

	}
	w1 = (arg >> 8) & 0xf;
	sub_402660(addr, w1, arg_10);
}

uint32_t sub_400528(uint32_t w0, int32_t w1) {
    uint32_t w2;
    w2 = w0;
    if (w2 == 0) {
    	return 1;
    }
    if (w2 == 1) {
    	    return 1;
    }
    if (w2 == 2) {
    	if (w1 == 0) {
    	    return 1;
	}
    }
    if (w2 == 3) {
    	if (w1 != 0) {
	    return 1;
	}
    }
    if (w2 == 4) {
    	if ( ((w1 >> 31) & 1 ) != 0) {
    	    return 1;
	}
    }
    if (w2 == 5) {
    	if (w1 > 0) {
    	    return 1;
	}
    }
    if (w2 == 6) {
    	if (w1 <= 0) {
    	    return 1;
	}
    }
    if (w2 == 7) {
    	w2 = 1; 
    } else {
    	w2 = 0;
    }
    w0 = ~w1;
    w0 = w2 & (w0 >> 31);
    return w0;
}

void sub_402704(char *addr, uint32_t arg) {
    uint32_t w2, var_s0;
    uint8_t *p;
    w2 = 0xffff;

    var_s0 = arg;

    if (arg > w2) {
	p = (uint8_t *) addr;
	*p &= 0xFFFFFFFE;
	*((uint32_t *) (addr + 4)) = 1;
	return;
    }
    write_data(addr, 0x3c, (char *) &var_s0, 4);
}

/* gestion des conditions ? */
void vm_sub_401794(char *addr, uint32_t arg) {
    uint32_t w0, w1;
    uint32_t eip;
    //printf("-> vm_sub_401794(addr = %p, arg = 0x%x)\n", addr, arg);

    w1 = sub_4025f4(addr, (arg >> 9) & 0xf);
    w0 = (arg >> 13) & 7;

    w0 = sub_400528(w0, w1);
    printf("w0 = 0x%x\n", w0);
    if (w0 == 0) {
	return;
    }
    if ( ((arg >> 8) & 1) != 0) {
	/* sauvegarde d'eip */
	printf("sauvegarde d'eip\n");
	eip = decode_ins(addr);
	sub_402660(addr, 0xf, eip);
    }
    sub_402704(addr, (arg >> 16) & 0xffffffff);
}

void vm_sub_40187c(char *addr, uint32_t arg) {
	printf("-> vm_sub_40187c : code me !\n");
	exit(EXIT_FAILURE);
}

void vm_sub_4018d0(char *addr, uint32_t arg) {
	printf("-> vm_sub_4018d0 : code me !\n");
	exit(EXIT_FAILURE);
}

void vm_sub_401970(char *addr, uint32_t arg) {
	printf("-> vm_sub_401970 : code me !\n");
	exit(EXIT_FAILURE);
}


void prepare_table(char *p) {
//	vm_ptr_t *fptr;
	int i;

//	fptr = (vm_ptr_t *) (p + 0x360);
	for (i = 0 ; i < 31; i++) {
		func_infos[i].fptr = vm_sub_400604;
		func_infos[i].name = NULL;
		//fptr[i] = vm_sub_400604;
	}

	func_infos[ 0].fptr = vm_sub_400d9c;
	func_infos[ 0].name = "set_reg";
	func_infos[ 1].fptr = vm_sub_400dac;
	func_infos[ 1].name = "or_imm";
	func_infos[ 2].fptr = vm_sub_401580; /* load word at imm + rn, store in rd */
	func_infos[ 2].name = "load_word";
	func_infos[ 3].fptr = vm_sub_401634;
	func_infos[ 4].fptr = vm_sub_4016e4; /* load byte at imm + rn, store in rd */
	func_infos[ 4].name = "load_byte";
	func_infos[ 5].fptr = vm_sub_401030;
	func_infos[ 6].fptr = vm_sub_4010ec;
	func_infos[ 7].fptr = vm_sub_4011b4;
	func_infos[ 7].name = "store_byte";
	func_infos[ 8].fptr = vm_sub_401794; /* gestion des conditions */
	func_infos[ 8].name = "jmp";
	func_infos[ 9].fptr = vm_sub_400d58;
	func_infos[10].fptr = vm_sub_400c90;
	func_infos[10].name = "xor";
	func_infos[11].fptr = vm_sub_400c20;
	func_infos[11].name = "or";
	func_infos[12].fptr = vm_sub_400bd0; /* & entre 2 registres */
	func_infos[12].name = "and";
	func_infos[13].fptr = vm_sub_400b78;
	func_infos[13].name = "lshift";
	func_infos[14].fptr = vm_sub_400b04; /* rd = rn >> rd */
	func_infos[14].name = "rshift";
	func_infos[15].fptr = vm_sub_400a8c;
	func_infos[16].fptr = vm_sub_400a08;
	func_infos[17].fptr = vm_sub_400978;
	func_infos[18].fptr = vm_sub_400918; /* addition entre 2 registres */
	func_infos[18].name = "add";
	func_infos[19].fptr = vm_sub_4008c4;
	func_infos[19].name = "sub";
	func_infos[20].fptr = vm_sub_400864;
	func_infos[21].fptr = vm_sub_4007ec;
	func_infos[22].fptr = vm_sub_400d24; /* incrémente la valeur du premier registre */
	func_infos[22].name = "inc_reg";
	func_infos[23].fptr = vm_sub_400ce0; /* décremente la valeur du premier registre */
	func_infos[23].name = "dec_reg";
	func_infos[24].fptr = vm_sub_401970;
	func_infos[25].fptr = vm_sub_4018d0;
	func_infos[26].fptr = vm_sub_40187c;
	func_infos[27].fptr = vm_sub_4005f4; /* nop */
	func_infos[28].fptr = vm_sub_4005fc;
	func_infos[28].name = "set_error_code_zero";
	func_infos[29].fptr = vm_sub_401490; /* syscall */
	func_infos[29].name = "syscall";
	func_infos[30].fptr = vm_sub_40077c; /* opération à la con */
	func_infos[30].name = "parity";
}

void set_iv(char *dst, char *src) {
	uint32_t w2;

	*((uint32_t *) (dst + 0x30)) = 0;
	*((uint32_t *) (dst + 0x34)) = 0;

	w2 = *((uint32_t *) src);
	*((uint32_t *) (dst + 0x38)) = w2;

	w2 = *((uint32_t *) (src+4));
	*((uint32_t *) (dst + 0x3c)) = w2;
}

void set_ctx(char *dst, char *src, uint32_t v1, uint32_t v2) {
	uint32_t w1, w2, w3, w4, w5, w6;
/*
0x000010: 65 78 70 61 6e 64 20 31 expand 1
0x000018: 36 2d 62 79 74 65 20 6b 6-byte k
0x000020: 0b ad b1 05 0b ad b1 05 ........
0x000028: 0b ad b1 05 0b ad b1 05 ........
0x000030: 0b ad b1 05 0b ad b1 05 ........
0x000038: 0b ad b1 05 0b ad b1 05 ........
*/
	w2 = *((uint32_t *) src);
	w5 = 0x7865;
	*((uint32_t *) (dst + 0x10)) = w2;

	w2 = *((uint32_t *) (src+4));
	w4 = 0x646e;
	*((uint32_t *) (dst + 0x14)) = w2;

	w2 = *((uint32_t *) (src+8));
	w3 = 0x2d36;
	*((uint32_t *) (dst + 0x18)) = w2;

	w2 = *((uint32_t *) (src+0xc));
	w5 = 0x61707865;
	*((uint32_t *) (dst + 0x1c)) = w2;

	w6 = *((uint32_t *) src);
	w2 = 0x6574;
	*((uint32_t *) (dst + 0x20)) = w6;

	w6 = *((uint32_t *) (src + 4));
	w4 = 0x3120646e;
	*((uint32_t *) (dst + 0x24)) = w6;

	w6 = *((uint32_t *) (src + 8));
	w3 = 0x79622d36;
	*((uint32_t *) (dst + 0x28)) = w6;

	w1 = *((uint32_t *) (src + 0xc));
	w2 = 0x6b206574;
	*((uint32_t *) (dst + 0x2c)) = w1;

	*((uint32_t *) dst) = w5;
	*((uint32_t *) (dst + 4)) = w4;
	*((uint32_t *) (dst + 8)) = w3;
	*((uint32_t *) (dst + 0xc)) = w2;
}

int prepare_memory(char *addr, uint32_t len, char **p) {
	int ret = 0;
	char *x19, *x4;
	void *tmp1, *ciphertext, *tmp3;
	int i = 0;
	uint32_t w0, w1;
	block_info_st *bi;

	printf("-> prepare_memory\n");
	addr0 = mmap((void *) 0x4000801000, 4096, PROT_READ|PROT_WRITE,
			MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, 0, 0);
	if (addr0 == (void *) -1) {
		perror("error during mmap");
		return -1;
	}

	addr1 = mmap((void *) 0x4000802000, 65536, PROT_READ|PROT_WRITE,
			MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, 0, 0);
	if (addr1 == (void *) -1) {
		perror("error during mmap");
		return -1;
	}

	for (i = 0; i < 32; i++) {
		mmu[i].addr = 0;
		mmu[i].idx = 0;
		mmu[i].flags = 2;
	}

	addr2 = mmap((void *) 0x4000812000, 4096, PROT_READ|PROT_WRITE,
			MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, 0, 0);
	if (addr2 == (void *) -1) {
		perror("error during mmap");
		return -1;
	}

	prepare_table(addr0);
	set_ctx(addr0 + 0x10, (char *) 0x510000, 0x80, 0);
	set_iv(addr0 + 0x10, (char *) (0x510000 + 0x20));

	w0 = *((uint8_t *) addr0);
	w0 &= 0xFFFFFFFE;
	*((uint8_t *) addr0) = w0;

	*((uint32_t *) (addr0 + 4)) = 0;
	*((uint64_t *) (addr0 + 8)) = 0;

	memcpy(addr1, (void *) 0x500000, len);
	p[0] = addr0;

	return 0;
}


void sub_4004a4(char *ctx, char *cipher, char *output, uint32_t len) {
    /*
	printf("ctx = %p, cipher = %p, output = %p, len = %u\n",
			ctx, cipher, output, len);
			*/
	if (len != 0) {
		ECRYPT_decrypt_bytes((ECRYPT_ctx *) ctx, cipher, output, len);
	}
}

char *mmu_handle(char *addr, uint32_t vm_addr) {
	uint64_t u1, u9, block_start, b3, b8;
	int i;
	char *src, *dst;

	for (i = 0; i < 32; i++) {
		/* si le bloc est marqué comme libre, passe au bloc suivant */
		if (((mmu[i].flags >> 1) & 1) == 0) {
			if (mmu[i].idx == (vm_addr / 64)) {
				dst = addr2 + 64 * i; // output
				mmu[i].addr = *((uint64_t *) (addr + 8));
				if (dst != 0)
					return dst;
				else
					break;
			}
		} 	
	}

	block_start = (vm_addr / 64) * 64;
	if (block_start > 0xffff)
		return NULL;
	
	b8 = -1;
	u9 = 0;
	for (i = 0; i < 32; i++) {
		/* bloc utilisé */
		if (((mmu[i].flags >> 1) & 1) == 0) {
			if (mmu[i].addr >= b8) {
				u9 = i;
				b8 = mmu[i].addr;
			}
		} else {
			dst = addr2 + 64 * i;
			mmu[i].flags &= 0xFFFFFFFC;
			mmu[i].idx = vm_addr / 64;
			mmu[i].addr = *((uint64_t *) (addr + 8));
			
			*((uint32_t *) (addr + 0x40)) = mmu[i].idx;
			*((uint32_t *) (addr + 0x44)) = 0;
			ECRYPT_decrypt_bytes(addr + 0x10, addr1 + block_start, dst, 64);
			return dst;
		}
	}

	dst = addr2 + 64 * u9;
	if ((mmu[u9].flags & 1) != 0) {
		/* le bloc doit être sauvegardé, il est rechiffré */
		u1 = mmu[u9].idx * 64;
		if (u1 <= 0xffff) {
			src = addr1 + (int32_t) u1;
			if (src != 0) {
				*((uint32_t *) (addr + 0x40)) = mmu[u9].idx;
				*((uint32_t *) (addr + 0x44)) = 0;

				ECRYPT_decrypt_bytes(addr + 0x10, dst, src, 64);
			}
		}
	}

	mmu[u9].flags &= 0xFFFFFFFC;
	mmu[u9].idx = vm_addr / 64;
	mmu[u9].addr = *((uint64_t *) (addr + 8));

	*((uint32_t *) (addr + 0x40)) = mmu[u9].idx;
	*((uint32_t *) (addr + 0x44)) = 0;
	ECRYPT_decrypt_bytes(addr + 0x10, addr1 + block_start, dst, 64);
	return dst;
}

uint32_t write_data(char *addr, uint32_t offset, char *src, uint32_t count) {
    	uint64_t u0, u1, u2, u4, u5, u6, u8, u9, u20, u21, u23, u24;
    	uint32_t w7;
    	char *ret, *x0, *x1, *x2, *x19, *x22;
    	int idx;
    	/*
	printf("-> write_data(addr = %p, offset = 0x%x, src = %p, count = %u)\n",
			addr, offset, src, count);
	*/

	x19 = src;
	u20 = count;
	u21 = offset;
	x22 = addr;

	if (count == 0) {
	    return 0;
	}

	/*
	if (count == 4) {
	    printf("*src = 0x%x\n", *((uint32_t *) src));
	}
	*/

	u23 = 64; /* block size */
	u24 = 0; /* total bytes read */
loc_402394:
	x0 = x22;
	u1 = u21;
	ret = mmu_handle(x0, u1);
	if (ret == NULL) {
	    return u24;
	}
	x0 = ret;
	u2 = u21 & 0x3f;
	u9 = u23 - u2;
	/* u9 = min(u9, u20); */
	if (u9 <= u20) {
	    u9 = u9;
	} else {
	    u9 = u20;
	}
	x2 = x0 + u2;
	if (u9 == 0) {
	    goto loc_4023e8;
	}
	u8 = u9 + 1;
	u6 = 1;
	u4 = 0;
	goto loc_4023d4;
loc_4023cc:
	u4 = u6;
	u6 = u5;
loc_4023d4:
	w7 = *((uint8_t *) (x19 + u4));
	u5 = u6 + 1;
	*((uint8_t *) (x2 + u4)) = w7;
	if (u5 != u8)
	    goto loc_4023cc;
loc_4023e8:
	x1 = addr2;
	u20 -= u9;
	u0 = x0 - x1; /* addr_bloc _ addr_base_cleartext */
	u0 = u0 >> 6; /* divise par 64 */
	idx = u0;
	u0 = 3 * u0;
	x1 = x22 + 8 * u0;
	//u0 = *((uint8_t *) (x1 + 0x68));
	u0 = mmu[idx].flags;
	u24 += u9; /* total octets lus */
	u0 |= 1;
	*((uint8_t *) (x1 + 0x68)) = u0;
	mmu[idx].flags = u0;
	x19 += u9;
	u21 += u9;
	/* nombre d'octets restant à lire */
	if (u20 != 0)
	    goto loc_402394;

	return u24;
}

uint32_t read_data(char *addr, uint32_t offset, char *dest, uint32_t count) {
	uint32_t w7, w22, w24;
	uint64_t u2, u4, u5, u6, u8, u9, u19, u20, u21, u22, u23, u24;
	char *ret, *x2, *x19, *x23;

	/*
	printf("-> read_data(addr = %p, offset = 0x%x, dest = %p, count = %u)\n",
			addr, offset, dest, count);
	*/
	if (count == 0)
		return 0;

	u20 = count;
	x23 = addr;
	u21 = offset;
	x19 = dest;

	u22 = 0;
	u24 = 64;

loc_4022dc:
	ret = mmu_handle(addr, u21);
	if (ret == NULL)
		return u22;

	u2 = u21 & 0x3f;
	/* nb d'octets dispo entre offset et fin du bloc */
	u9 = u24 - u2;
	if (u9 <= u20) {
		u9 = u9;
 	} else {
		u9 = u20;
	}
	x2 = ret + u2;
	if (u9 == 0)
		goto loc_402330;
	u8 = u9 + 1;
	u6 = 1;
	u4 = 0;
	goto loc_40231c;
loc_402314:
	u4 = u6;
	u6 = u5;
loc_40231c:
	w7 = *((uint8_t *) (x2 + u4));
	u5 = u6 + 1;
	*((uint8_t *)(x19 + u4)) = w7;
	if (u5 != u8)
		goto loc_402314;
loc_402330:
	u20 -= u9;
	u22 += u9;
	x19 += u9;
	u21 += u9;
	if (u20 != 0)
		goto loc_4022dc;
loc_402344:
	/*
        switch(count) {
            case 1:
              printf("result = 0x%x\n", *((uint8_t *) dest));
              break;
            case 2:
              printf("result = 0x%x\n", *((uint16_t *) dest));
              break;
            case 4:
              printf("result = 0x%x\n", *((uint32_t *) dest));
              break;
            default:
              hexdump(dest, count);
        }
        */
	return u22;
}

/* load eip ? */
int decode_ins(char *addr) {
	//printf("\n-> decode_ins: addr = %p\n", addr);
	uint32_t result;
	uint32_t ret;

	ret = read_data(addr, 0x3c, (char *) &result, 4);
	if (ret == 4)
		return result;
	return -1;
}

uint32_t start_vm(char *addr) {
	vm_ptr_t fptr;
	uint32_t w0, w3, w23, w24, w25;
	uint32_t arg_40 = 0, arg_4c = 0, arg_48 = 0;
	uint32_t arg;
	uint64_t u0, u1, u3, u20, u21, u22;
	uint64_t eip, next_eip, func_index;
	int ret;

	w0 = *((uint8_t *) addr);
	if (!w0) {
		return *((uint32_t *) (addr+4));
	}

	w23 = 0xFFFF;
	w24 = 4;
	w25 = 2;

	goto loc_4027b8;

loc_402788:
	printf("-> loc_402788 : code me!\n");
	exit(EXIT_FAILURE);
loc_4027b8:
	ret = decode_ins(addr);
	if (ret == -1) {
		w0 = *((uint8_t *) addr);
		w0 &= 0xFFFFFFFE;
		*((uint8_t *) addr) = w0;
		*((uint8_t *) (addr + 4)) = 1;
		return 1;
	}

	u20 = ret;
	eip = u20;

	u21 = read_data(addr, u20, (char *) &arg_4c, 1);
	func_index = arg_4c;
	if (u21 != 1) {
		w0 = *((uint8_t *) addr);
		w0 &= 0xFFFFFFFE;
		*((uint8_t *) addr) = w0;
		*((uint8_t *) (addr + 4)) = 1;
		return 1;
	}
	u1 = u20;
	w3 = arg_4c;
	if (w3 > 0x1f) {
		w0 = *((uint8_t *) addr);
		w0 &= 0xFFFFFFFE;
		*((uint8_t *) addr) = w0;
		*((uint8_t *) (addr + 4)) = 2;
		return 2;
	}

	u22 = (w3 > 8) ? w25 : w24;
	u3 = u22;

	arg_48 = 0;
	u0 = read_data(addr, u1, (char *) &arg_48, u3); 
	arg = arg_48;
	if (u0 != u22) {
	    printf("code me !\n");
	    exit(EXIT_FAILURE);
	}
	/* augmente next eip */
	u20 += u0;
	arg_40 = u20;
	next_eip = arg_40;

	if (u20 > 0xffff)
	    goto loc_402788;

	write_data(addr, 0x3c, &arg_40, 4);
	
	u0 = arg_4c + 0x6c;
	//fptr = *((vm_ptr_t *) (addr + 8 * u0));
	//(*fptr)(addr, arg_48);
	fptr = func_infos[func_index].fptr;
	if (func_infos[func_index].name == NULL) {
		fprintf(stderr, "Missing name for func %d\n", func_index);
		exit(EXIT_FAILURE);
	}
	printf("\n[%lu] %s(0x%x = %u)\n",
			eip, func_infos[func_index].name,
			arg, arg);
	(*fptr)(addr, arg);
	w0 = *((uint8_t *) addr);
	if ((w0 & 1) != 0)
	    goto loc_4027b8;


	u21 = *((uint32_t *) (addr + 4));
	return u21;
}

void sub_402914(char *addr) {
	uint32_t w1;
	char *ret;

	w1 = *((uint8_t *) addr);
	w1 |= 1;
	*((uint8_t *) addr) = w1;

	ret = start_vm(addr);
	printf("ret = %x\n", ret);
}

int sub_4000b0(void) {
	char *p[2];
	char *x0;

	int ret = 0;
	ret = prepare_memory((char *) 0x500000, 0x10000, p);
	if (ret != 0) {
		return -1;
	}
	x0 = p[0];
	printf("x0 = %p\n", x0);
	sub_402914(x0);
	return 0;

}

void new_prog_2(int argc, char **argv) {
	int ret;
	/* stocke à mem_data + 0x10018 l'adresse de ENV */
	ret = sub_4000b0();
	exit(ret);
}

/* sub_400514 */
void new_prog(void) {
	/* en théorie, passe argc et argv à new_prog_2 */
	new_prog_2(1, NULL);
}


void sub_1010c(void) {
	void *tmp;
	Elf64_Shdr *data_shdr;
	char *data_addr, *src_addr, *remap_src_addr;
	uint32_t ret, src_len;

	tmp = mmap((void *) 0x10400000, 0x3000, PROT_READ|PROT_WRITE,
			MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
	if (tmp == (void *) -1) {
		perror("error during mmap");
		exit(EXIT_FAILURE);
	}
	mem_new_prog = (char *) tmp;

	data_shdr = find_shdr(".data", badbios);
	if (!data_shdr) {
		fprintf(stderr, "cannot find section header for .data");
		exit(EXIT_FAILURE);
	}
	data_addr = badbios + data_shdr->sh_offset;
	src_addr = *((char **) (data_addr + 16 + 16));
	remap_src_addr = REMAP_VADDR(data_shdr, data_addr, src_addr);
	src_len = *((uint32_t *) (data_addr + 16 + 24));

	ret = load_new_prog(remap_src_addr, mem_new_prog, src_len, 0x3000);
	if (ret == 0) {
		exit(EXIT_FAILURE);
	}

	if (mprotect(mem_new_prog, 0x3000, PROT_EXEC|PROT_READ) == -1) {
		perror("mprotect:");
		exit(EXIT_FAILURE);
	}

	tmp = mmap((void *) 0x500000, 0x11000, PROT_READ|PROT_WRITE,
			MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, 0, 0);
	if (tmp == (void *) -1) {
		perror("error during mmap");
		exit(EXIT_FAILURE);
	}
	mem_data = tmp;

	src_addr = *((char **) (data_addr + 0x38 + 16));
	remap_src_addr = REMAP_VADDR(data_shdr, data_addr, src_addr);
	src_len = *((uint32_t *) (data_addr + 0x38 + 24));

	/* copie les données chiffrées de la section .data du nouveau binaire
	 * */
	printf("src_addr = %p, remap_src_addr = %p\n", src_addr, remap_src_addr);
	memcpy(mem_data, remap_src_addr, src_len);
	hexdump(mem_data, 512);

	if (mprotect(mem_data, 0x11000, PROT_READ|PROT_WRITE) == -1) {
		perror("mprotect:");
		exit(EXIT_FAILURE);
	}

	new_prog();
}


int main(int argc, char **argv) {
	void *tmp;
	struct stat st;
	int fd;

	if (argc != 2) {
		fprintf(stderr, "usage: %s badbios\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	if (stat(argv[1], &st) == -1) {
		perror("error during stat");
		exit(EXIT_FAILURE);
	}

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		perror("error during open");
		exit(EXIT_FAILURE);
	}

	do_init();

	tmp = mmap((void *) 0x20000, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (tmp == (void *) -1) {
		perror("error during mmap");
		exit(EXIT_FAILURE);
	}
	badbios = (char *) tmp;
	printf("badbios = %p\n", badbios);

	//dump_elf_sections(badbios);
	sub_1010c();

	exit(EXIT_SUCCESS);
}

