/*
 * Copyright (c) 2015 Jean-Philippe Ouellet <jpo@vt.edu>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Permission to republish this is *NOT* granted unless you massively clean
 * it up. You may remove this statement after it has been cleaned up.
 */

/*
 *  Cleaned up and improved on 09/26/2015 Conor Patrick
 */

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/err.h>

#include <stdint.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <zlib.h>

// Use a mask to flip N bits
struct bitsaver_mask
{
    int bits;
    int done;
    size_t max;
    size_t* pos;
};

// Max size to decompress into
size_t MAX_MEM_SIZE = (1<<29);

struct bitsaver
{
    char* inflated;
    char* data;

    off_t data_size;
    size_t inflated_max_size;
    size_t inflated_size;

    uint8_t goodhash[SHA_DIGEST_LENGTH];
};

int bs_check_hash(const struct bitsaver* bs)
{
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(bs->inflated, bs->inflated_size, hash);
    return  (bcmp(bs->goodhash, hash, SHA_DIGEST_LENGTH) == 0);
}


// Flips N bits according to mask
void BITFLIP(uint8_t* buf, struct bitsaver_mask* bm)
{
    int i;
    for (i = 0; i < bm->bits; i++)
    {
        if(bm->pos[i])buf[bm->pos[i]/8] ^=  1<<(bm->pos[i] % 8);
    }
}

typedef enum
{
    BS_SUCCESS = 0,
    BS_FAIL,
} bitsaver_t;

//  init a mask with N bits
struct bitsaver_mask* bs_mask_init(int bits)
{
    struct bitsaver_mask* bm = malloc(sizeof(struct bitsaver_mask));
    if (bm == NULL)
    {
        err(1,"malloc");
    }
    bm->pos = malloc(sizeof(size_t)*bits);
    if (bm->pos == NULL)
    {
        err(1,"malloc");
    }

    bm->bits = bits;
    bm->done = 0;

    return bm;
}

void bs_mask_destroy(struct bitsaver_mask* bm)
{
    free(bm->pos);
    free(bm);
}

void bs_mask_set_max(struct bitsaver_mask* bm,int max)
{
    bm->max = max;
}
void bs_mask_clear(struct bitsaver_mask* bm)
{
    memset(bm->pos, 0, sizeof(size_t)*bm->bits);
}


// For testing
void bs_mask_print(struct bitsaver_mask* bm)
{
    int i;
    for (i=0; i < bm->bits; i ++)
        printf(" %zd ",bm->pos[i]);
    printf("\n");
}


void bs_mask_inc(struct bitsaver_mask* bm)
{
    int i;
    size_t* lsd = bm->pos;
    size_t* end = lsd + bm->bits - 1;
    do
    {
        (*lsd)++;
        if (*lsd == bm->max)
        {
            *lsd = 0;
            if (lsd == end)
            {
                bm->done = 1;
                return;
            }
        }
        if (lsd == end)
        {
            break;
        }
        lsd++;
    }
    while(*(lsd-1)==0);
}

// Flip all bits in inflated buffer
bitsaver_t bs_check_bits_inflate(struct bitsaver* bs, struct bitsaver_mask* bm)
{

    // Check without any flipping
    if (bs_check_hash(bs))
    {
        return BS_SUCCESS;
    }

    int j;
    bm->max = bs->inflated_size*8;
    for(bs_mask_clear(bm); !bm->done; bs_mask_inc(bm))
    {
        BITFLIP(bs->inflated, bm);
        if (bs_check_hash(bs))
        {

            return BS_SUCCESS;
        }
        BITFLIP(bs->inflated, bm);

    }
    return BS_FAIL;
}

// Flip all bits in compressed buffer and bit flip each new uncompressed version
bitsaver_t bs_check_bits_compressed(struct bitsaver* bs, int bits)
{

    struct bitsaver_mask* bm_inflate = bs_mask_init(bits);

    // Check without any flips
    size_t len = bs->inflated_max_size;
    int i,j;

    bs->inflated_size = bs->inflated_max_size;

    printf("Checking the uncompressed version\n");
    int ec;
    while(ec=(uncompress(bs->inflated, &bs->inflated_size, bs->data, bs->data_size)) == Z_BUF_ERROR)
    {
        free(bs->inflated);
        bs->inflated_max_size *= 0x10;
        if (bs->inflated_max_size > MAX_MEM_SIZE)
        {
            errx(1,"decompressing file exceeded %zd bytes.\n",MAX_MEM_SIZE);
        }
        bs->inflated = malloc(bs->inflated_max_size);
        if(bs->inflated == NULL)
        {
            err(1,"malloc");
        }
        bs->inflated_size = bs->inflated_max_size;
    }
    if( ec == Z_OK )
    {
        if (bs_check_bits_inflate(bs, bm_inflate) == BS_SUCCESS)
        {
            return BS_SUCCESS;
        }
    }


    printf("Checking the compressed version\n");
    struct bitsaver_mask* bm = bs_mask_init(bits);
    bs_mask_set_max(bm, bs->data_size*8);
    for(bs_mask_clear(bm); !bm->done; bs_mask_inc(bm))
    {
        BITFLIP(bs->data, bm);

        bs->inflated_size = bs->inflated_max_size;

        if( uncompress(bs->inflated, &bs->inflated_size, bs->data, bs->data_size) == Z_OK )
        {
            if (bs_check_bits_inflate(bs,bm_inflate) == BS_SUCCESS)
            {
                return BS_SUCCESS;
            }

        }

        BITFLIP(bs->data, bm);
    
    }

    bs_mask_destroy(bm);
    bs_mask_destroy(bm_inflate);

    return BS_FAIL;
}


int bs_init(struct bitsaver* bs, uint8_t* fn, uint8_t* hash) {
    struct stat sbuf;
    uint8_t* data;
    int fd;
    BIGNUM *bn = NULL;
    memset(bs, 0, sizeof(struct bitsaver));

    printf("loading file %s  hash %s\n",fn,hash);

    if (BN_hex2bn(&bn, hash) == 0)
    {
        unsigned long e = ERR_get_error();
        errx(1, "BN_bex2bn: %s\n", ERR_error_string(e,NULL));
    }

    if(BN_num_bytes(bn) != SHA_DIGEST_LENGTH)
    {
        errx(1, "Must provide a SHA1 hash\n");
    }

    if (BN_bn2bin(bn, bs->goodhash) == 0)
    {
        unsigned long e = ERR_get_error();
        errx(1, "BN_bn2bin: %s\n", ERR_error_string(e,NULL));
    }

    BN_free(bn);

    if ((fd = open(fn, O_RDONLY)) == -1)
    {
        err(1, "open");
    }

    if (fstat(fd, &sbuf) == -1)
    {
        err(1, "stat");
    }

    if ((data = mmap(NULL, sbuf.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
    {
        err(1, "mmap");
    }

    if(close(fd) != 0)
    {
        err(1,"close");
    }

    bs->data = data;
    bs->data_size = sbuf.st_size;
    bs->inflated_max_size = sbuf.st_size;

    bs->inflated = malloc(bs->inflated_max_size);

    if (bs->inflated == NULL)
    {
        err(1,"malloc"); 
    }

    return 0;
}

void bs_destroy(struct bitsaver* bs)
{
    free(bs->inflated);
    if(munmap(bs->data, bs->data_size) != 0)
    {
        err(1,"munmap");
    }
}

void bs_save(struct bitsaver* bs, const char* fn)
{
    int fd = open(fn, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
    
    if (fd < 0)
    {
        err(1,"open");
    }

    if (write(fd, bs->inflated, bs->inflated_size) < 0)
    {
        err(1,"write");
    }

    if (close(fd) < 0)
    {
        err(1,"close");
    }
}

int main(int argc, char *argv[])
{

    int fd,bits=3;
    struct bitsaver bs;
    const char* output_fn = "out.bin";

    int opt,offset=0;
    while ((opt = getopt (argc, argv, "b:h")) != -1)
    {
        switch (opt)
        {
            case 'b':
                bits = atoi(optarg);
                offset += 2;
                break;
            case 'h':
                fprintf(stderr,"bitsaver\n"
                        "    -h  print help\n"
                        "    -b <bits>  the upper bound for the number of bits to try permuting on the file (default 3).\n"
                        );
                exit(0);
                break;
        }
    }
    if (argc + offset< 3) 
    {
        errx(1, "usage: %s [ -b <bits> | -h ] <zlib-file> <hash>\n", argv[0]);
    }


    bs_init(&bs, argv[1+offset], argv[2+offset]);

    bitsaver_t r = bs_check_bits_compressed(&bs,bits);

    if (r == BS_SUCCESS)
    {
        printf("Found original file.  Saving to %s\n",output_fn);
        bs_save(&bs, output_fn);
    }
    else
    {
        printf("Could not find original file after checking all combinations ( ~ %zd choose %d + %zd choose %d ).\n",
                bs.inflated_size, bits, bs.data_size,bits);
    }

    bs_destroy(&bs);

    return 0;
}
