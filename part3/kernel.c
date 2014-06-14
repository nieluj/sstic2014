#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

unsigned char *mem;

void sb(uint16_t addr, uint8_t v) {
    printf("sb(0x%x, 0x%x)\n", addr, v);
}

uint8_t lb(uint16_t addr) {
    uint8_t ret = 0;
    printf("lb(0x%x) = 0x%x\n", addr, ret);
    return ret;
}

/* store word */
void store_word(uint16_t r0, uint16_t r1) {
    sb(r0 + 1, r1);
    sb(r0, r1 << 4);
}

/* load word */
uint16_t load_word(uint16_t r0) {
    uint8_t r3, r4;
    r3 = lb(r0 +1);
    r4 = lb(r0);

    r0 = (r3 | (r4 >> 4));
    return r0;
}

void sub_e6(uint16_t r0, uint16_t r1) {
	uint16_t r5, r8, r9, r10, r11, r12, r13, r14;

	printf("sub_e6(r0 = 0x%x, r1 = 0x%x)\n", r0, r1);
	r14 = r0;
	r13 = 0xfc00;
	r12 = 0xf000;
	r8 = 0;
	r9 = 0;
	r10 = 1;
	r11 = 0;

loc_fa:
	if (r1 == 0) {
	    return;
	}

	r9 = r0 + r8 - 0xf000;
	if (r9 < 0) {
	    /* loc_10c */
	    r9 = lb(r0 + r8);
	    sb(0xfc00 + r11, r9);
	    r8++;
	    r1--;
	    goto loc_fa;
	}
	r9 = r0 + r8 - 0xfc00;
	if (r9 > 0) {
	    /* loc_10c */
	    r9 = lb(r0 + r8);
	    sb(0xfc00 + r11, r9);
	    r8++;
	    r1--;
	    goto loc_fa;
	}

	/* plus de place dans la zone secrete */

	/* loc_11a */
	/* copie la chaine "error printing at unallowed address */
	sub_e6(0xfe26, 0x33);

	/* loc_28 */
	sb(0xfc10, 1);
	r5 = load_word(0xfc22);
	r0 = load_word(0xfc20);
	sub_e6(r0, r5);

	exit(EXIT_SUCCESS);
}

void set_memory(uint16_t addr, uint16_t r1, uint16_t count) {
loc_d6:
	if (count == 0) {
	    return;
	}
	count--;
	sb(addr + count, r1);
	goto loc_d6;
}

void sub_28(void) {
    sb(0xfc10, 1);
    r5 = load_word(0xfc22);
    r0 = load_word(0xfc20);
    sub_e6(r0, r5);
    exit(EXIT_SUCCESS);
}

void sub_36(void) {
    r5 = load_word(0xfc22);
    r0 = load_word(0xfc20);
    sub_e6(r0, r5);
    exit(EXIT_SUCCESS);
}

void sub_4a(void) {
    r0 = load_word(0xfc20);
    r6 = 0xfc12;
    r1 = 1;
    r4 = 0;

loc_5a:
    r5 = lb(r6 + 1);
    r2 = lb(r6);
    r3 = lb(r6);

    r3 -= r2;
    if (r3 != 0)
    	goto loc_5a;
    r2 = r2 * 0x1000;
    r1 = r2 | r5;
    store_word(r0, r1);
    exit(EXIT_SUCCESS);
}


uint16_t do_start(uint16_t r0) {
    uint16_t r1, r4, r5, tmp;

    if (r0 == 0) {
	/* loc_70 */
	/* copie la chaîne system reset dans la zone secrete */
	sub_e6(0xfe86, 0xe);

	/* stocke les handlers des syscall */
	store_word(0xf000, 0xfd28);
	store_word(0xf002, 0xfd36);
	store_word(0xf004, 0xfd4a);

	set_memory(0xfc20, 0, 0x36);
	store_word(0xfc3a, 0xeffe);
	/* retour en userland */
	exit(EXIT_SUCCESS);
    }
    if (r0 > 3) {
    	/* loc_1e, charge 'error: undefined system call' */
    	sub_e6(0xfe5a, 0x2b);
    	sb(0xfc10, 1); /* fd */
	r5 = load_word(0xfc22);
	r0 = load_word(0xfc20);
	sub_e6(r0, r5);

	exit(EXIT_SUCCESS);
    }
    if (r0 == 1) {
    	sub_28();
    } else if (r0 == 2) {
    	sub_36();
    } else if (r0 == 3) {
    	sub_4a();
    }
    exit(EXIT_SUCCESS);
}

int main(int arc, char **argv) {
    uint16_t r0 = 0;

    r0 = do_start(r0);
    return r0;
}
