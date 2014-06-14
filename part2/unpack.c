#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdint.h>
#include <string.h>
#include <elf.h>

#define PACKED_DATA_START 0x310c8 /* @0x21020 */
#define PACKED_DATA_SIZE  0x1E84  /* @0x21028 */
#define DATA_SECTION_OFFSET 0x1000
#define DATA_SECTION_ADDR  0x21000
#define NUM_SECTIONS 5

#define RODATA_SECTION_OFFSET 0x2b38

int unpack(char *src, char *dst, uint32_t slen, uint32_t dlen) {
	char *p;
	uint8_t b;
	uint64_t off1, off2, off3;
	uint64_t a1[8] = { 4, 1, 2, 1, 4, 4, 4, 4 };
	uint64_t a2[8] = { 0, 0, 0, 0xFFFFFFFFFFFFFFFF, 0, 1, 2, 3 };
	int i, src_idx = 0, pdst_idx, dst_idx = 0;

	do {
		pdst_idx = dst_idx;

		b = src[src_idx++];

		off1 = b >> 4;
		off2 = b & 0xf;

		if ((off1 == 0xf) && (src_idx < slen)) {
			do {
				b = src[src_idx++];
				off1 += b;
			} while (src_idx == slen || b == 0xff);
		}

		if (dst_idx + off1 > dlen - 12)
			break;

		if (src_idx + off1 > slen - 8)
			break;

		do {
			memcpy(dst + dst_idx, src + src_idx, 8);
			dst_idx += 8; src_idx += 8;
		} while (dst_idx < (pdst_idx + off1));

		src_idx += off1 - (dst_idx - pdst_idx);

		off3 = *((uint16_t *) (src + src_idx));
		src_idx += 2;

		if (off2 == 0xf) {
			do {
				if (src_idx >= slen - 6)
					break;
				b = src[src_idx++];
				off2 += b;
			} while (b == 0xff);
		}

		p = dst + pdst_idx + off1 - off3;
		if (off3 <= 7) {
			for (i = 0; i < 4; i ++)
				p[i + off3] = p[i];

			memcpy(p + off3 + 4, p + a1[off3], 4);
			p += a1[off3] - a2[off3];
		} else {
			memcpy(p + off3, p, 8);
			p += 8;
		}

		for (i = 0; i + 4 < off2 ; i += 8) {
			memcpy(dst + pdst_idx + off1 + 8 + i, p + i, 8);
		}

		dst_idx = pdst_idx + off1 + off2 + 4;
	} while (1);

	if (src_idx + off1 == slen) {
		if (off1 != 0) {
			for (i = 0; i < off1 + 1; i++) {
				dst[dst_idx + i] = src[src_idx + i];
			}
			dst_idx += off1;
		}
	}

	return dst_idx;
}

void restore_program(char *output, char *stext, int stext_size, int rodata_offset, char *sdata, int sdata_size) {
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	Elf64_Shdr shdrs[NUM_SECTIONS]; /* NULL section + text + rodata + data + strtab */
	char *strtab;
	int fd, strtab_size = 0;

	memset(shdrs, 0, NUM_SECTIONS * sizeof(Elf64_Shdr));

	/* Fix two program headers */
	phdr = (Elf64_Phdr *) (stext + sizeof(Elf64_Ehdr));
	phdr->p_type = PT_LOAD;
	phdr->p_flags = PF_X | PF_R;
	phdr->p_offset = 0;
	phdr->p_vaddr = phdr->p_paddr = 0x400000;
	phdr->p_filesz = phdr->p_memsz = stext_size;
	phdr->p_align = 0x10000;

	phdr++;
	phdr->p_type = PT_LOAD;
	phdr->p_flags = PF_W | PF_R;
	phdr->p_offset = 0x3000;
	phdr->p_vaddr = phdr->p_paddr = 0x500000;
	phdr->p_filesz = phdr->p_memsz = sdata_size;
	phdr->p_align = 0x10000;

	strtab = malloc(1024);

	/* section NULL */
	shdrs[0].sh_name = strtab_size;
	memcpy(strtab, "", 1); strtab_size += 1;

	/* section .text */
	shdrs[1].sh_name = strtab_size;
	shdrs[1].sh_type = SHT_PROGBITS;
	shdrs[1].sh_flags = SHF_ALLOC | SHF_EXECINSTR;
	shdrs[1].sh_addr = 0x400000 + sizeof(Elf64_Ehdr) + 2 * sizeof(Elf64_Phdr);
	shdrs[1].sh_offset = sizeof(Elf64_Ehdr) + 2 * sizeof(Elf64_Phdr);
	shdrs[1].sh_size = rodata_offset;
	shdrs[1].sh_addralign = 4;
	memcpy(strtab + strtab_size, ".text", strlen(".text") + 1);
	strtab_size += strlen(".text") + 1;

	/* section .rodata */
	shdrs[2].sh_name = strtab_size;
	shdrs[2].sh_type = SHT_PROGBITS;
	shdrs[2].sh_flags = SHF_ALLOC;
	shdrs[2].sh_addr = 0x400000 + rodata_offset;
	shdrs[2].sh_offset = rodata_offset;
	shdrs[2].sh_size = (stext_size - rodata_offset);
	shdrs[2].sh_addralign = 8;
	memcpy(strtab + strtab_size, ".rodata", strlen(".rodata") + 1);
	strtab_size += strlen(".rodata") + 1;

	/* section .data */
	shdrs[3].sh_name = strtab_size;
	shdrs[3].sh_type = SHT_PROGBITS;
	shdrs[3].sh_flags = SHF_ALLOC | SHF_WRITE;
	shdrs[3].sh_addr = 0x500000;
	shdrs[3].sh_offset = stext_size;
	shdrs[3].sh_size = sdata_size;
	shdrs[3].sh_addralign = 8;
	memcpy(strtab + strtab_size, ".data", strlen(".data") + 1);
	strtab_size += strlen(".data") + 1;

	/* section .shstrab */
	shdrs[4].sh_name = strtab_size;
	shdrs[4].sh_type = SHT_STRTAB;
	shdrs[4].sh_offset = stext_size + sdata_size;
	memcpy(strtab + strtab_size, ".shstrtab", strlen(".shstrtab") + 1);
	strtab_size += strlen(".shstrtab") + 1;
	shdrs[4].sh_size =  strtab_size;
	shdrs[4].sh_addralign = 1;

	ehdr = (Elf64_Ehdr *) stext;
	ehdr->e_shoff = stext_size + sdata_size + strtab_size;
	ehdr->e_shnum = NUM_SECTIONS;
	ehdr->e_shstrndx = NUM_SECTIONS - 1;

	fd = creat(output, S_IRWXU);
	if (fd == -1) {
		perror("creat");
		exit(EXIT_FAILURE);
	}
	write(fd, stext, stext_size);
	write(fd, sdata, sdata_size);
	write(fd, strtab, strtab_size);
	write(fd, shdrs, NUM_SECTIONS * sizeof(Elf64_Shdr));
	close(fd);
}

int main(int argc, char **argv) {
	struct stat st;
	int fd;
	char *stext, *sdata;
	char *badbios;
	char *output;

	if (argc != 3) {
		fprintf(stderr, "usage: %s badbios output\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	output = argv[2];

	if (stat(argv[1], &st) == -1) {
		perror("error during stat");
		exit(EXIT_FAILURE);
	}

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		perror("error during open");
		exit(EXIT_FAILURE);
	}

	badbios = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (badbios == MAP_FAILED) {
		perror("mmap");
		exit(EXIT_FAILURE);
	}
	close(fd);


	stext = mmap(NULL, 0x3000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
	if (stext == MAP_FAILED) {
		perror("mmap");
		exit(EXIT_FAILURE);
	}

	sdata = mmap(NULL, 0x11000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
	if (sdata == MAP_FAILED) {
		perror("mmap");
		exit(EXIT_FAILURE);
	}

	unpack(badbios + DATA_SECTION_OFFSET + PACKED_DATA_START - DATA_SECTION_ADDR,
			stext, PACKED_DATA_SIZE, 0x3000);
	memcpy(sdata, badbios + DATA_SECTION_OFFSET + 0x210b0 - DATA_SECTION_ADDR, 0x10018);

	restore_program(output, stext, 0x3000, RODATA_SECTION_OFFSET, sdata, 0x11000);

	exit(EXIT_SUCCESS);
}
