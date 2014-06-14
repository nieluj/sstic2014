#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "ecrypt-sync.h"

void init_ctx(ECRYPT_ctx *ctx) {
    int i;

    ctx->input[0] = 0x61707865;
    ctx->input[1] = 0x3120646e;
    ctx->input[2] = 0x79622d36;
    ctx->input[3] = 0x6b206574;

    for (i = 4; i < 12; i++) {
    	ctx->input[i] = 0x05b1ad0b;
    }
    for (i = 12; i < 16; i++) {
    	ctx->input[i] = 0;
    }

}

int main(int argc, char **argv) {
    char *input, *output;
    unsigned char *input_data;
    struct stat in_st;
    int input_fd, output_fd;
    int i;
    unsigned char tmp[64];
    ECRYPT_ctx ctx;

    if (argc != 3) {
    	fprintf(stderr, "usage: %s input output\n", argv[0]);
    	exit(EXIT_FAILURE);
    }

    input = argv[1]; output = argv[2];

    init_ctx(&ctx);

    if (stat(input, &in_st) == -1) {
    	perror("stat");
    	exit(EXIT_FAILURE);
    }

    input_fd = open(input, O_RDONLY);
    if (input_fd == -1) {
    	perror("open");
    	exit(EXIT_FAILURE);
    }

    output_fd = creat(output, S_IRWXU);
    if (output_fd == -1) {
    	perror("open");
    	exit(EXIT_FAILURE);
    }

    input_data = mmap(NULL, in_st.st_size, PROT_READ, MAP_SHARED, input_fd, 0);
    if (input_data == (void *) -1) {
    	perror("mmap");
    	exit(EXIT_FAILURE);
    }

    ECRYPT_init();
    for (i = 0; i < (in_st.st_size / 64); i++) {
    	ECRYPT_decrypt_bytes(&ctx, input_data + 64 * i, tmp, 64);
    	write(output_fd, tmp, 64); 
    }

    close(output_fd);
    munmap(input_data, in_st.st_size);
    close(input_fd);

    exit(EXIT_SUCCESS);
}
