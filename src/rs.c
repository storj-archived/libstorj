/*
 * rs.c -- forward error correction based on Vandermonde matrices
 * 980624
 * (C) 1997-98 Luigi Rizzo (luigi@iet.unipi.it)
 * (C) 2001 Alain Knaff (alain@knaff.lu)
 * (C) 2017 Storj Labs, Inc.
 *
 * Portions derived from code by Phil Karn (karn@ka9q.ampr.org),
 * Robert Morelos-Zaragoza (robert@spectra.eng.hawaii.edu) and Hari
 * Thirumoorthy (harit@spectra.eng.hawaii.edu), Aug 1995

 * Reimplement by Jannson (20161018): compatible for golang version of
 * https://github.com/klauspost/reedsolomon
 *
 * Modifications by Braydon Fuller (braydon@storj.io) to support memory
 * mapped files.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials
 *    provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
 * OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 */

/*
 * The following parameter defines how many bits are used for
 * field elements. The code supports any value from 2 to 16
 * but fastest operation is achieved with 8 bit elements
 * This is the only parameter you may want to change.
 */
#define GF_BITS  8  /* code over GF(2**GF_BITS) - change to suit */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rs.h"

/*
 * stuff used for testing purposes only
 */

#ifdef  TEST
#define DEB(x)
#define DDB(x) x
#define DEBUG   0   /* minimal debugging */

#include <sys/time.h>
#define DIFF_T(a,b)                                                     \
    (1+ 1000000*(a.tv_sec - b.tv_sec) + (a.tv_usec - b.tv_usec) )

#define TICK(t)                                         \
    {struct timeval x;                                  \
        gettimeofday(&x, NULL);                         \
        t = x.tv_usec + 1000000* (x.tv_sec & 0xff );    \
    }
#define TOCK(t)                                 \
    { u_long t1; TICK(t1);                      \
        if (t1 < t) t = 256000000 + t1 - t;     \
        else t = t1 - t;                        \
        if (t == 0) t = 1;}

u_long ticks[10];   /* vars for timekeeping */
#else
#define DEB(x)
#define DDB(x)
#define TICK(x)
#define TOCK(x)
#endif /* TEST */

/*
 * You should not need to change anything beyond this point.
 * The first part of the file implements linear algebra in GF.
 *
 * gf is the type used to store an element of the Galois Field.
 * Must constain at least GF_BITS bits.
 *
 * Note: uint8_t will work up to GF(256) but int seems to run
 * faster on the Pentium. We use int whenever have to deal with an
 * index, since they are generally faster.
 */
/*
 * AK: Udpcast only uses GF_BITS=8. Remove other possibilities
 */
#if (GF_BITS != 8)
#error "GF_BITS must be 8"
#endif
typedef uint8_t gf;

#define GF_SIZE ((1 << GF_BITS) - 1)    /* powers of \alpha */

/*
 * Primitive polynomials - see Lin & Costello, Appendix A,
 * and  Lee & Messerschmitt, p. 453.
 */
static char *allPp[] = {    /* GF_BITS  polynomial      */
    NULL,           /*  0   no code         */
    NULL,           /*  1   no code         */
    "111",          /*  2   1+x+x^2         */
    "1101",         /*  3   1+x+x^3         */
    "11001",            /*  4   1+x+x^4         */
    "101001",           /*  5   1+x^2+x^5       */
    "1100001",          /*  6   1+x+x^6         */
    "10010001",         /*  7   1 + x^3 + x^7       */
    "101110001",        /*  8   1+x^2+x^3+x^4+x^8   */
    "1000100001",       /*  9   1+x^4+x^9       */
    "10010000001",      /* 10   1+x^3+x^10      */
    "101000000001",     /* 11   1+x^2+x^11      */
    "1100101000001",        /* 12   1+x+x^4+x^6+x^12    */
    "11011000000001",       /* 13   1+x+x^3+x^4+x^13    */
    "110000100010001",      /* 14   1+x+x^6+x^10+x^14   */
    "1100000000000001",     /* 15   1+x+x^15        */
    "11010000000010001"     /* 16   1+x+x^3+x^12+x^16   */
};


/*
 * To speed up computations, we have tables for logarithm, exponent
 * and inverse of a number. If GF_BITS <= 8, we use a table for
 * multiplication as well (it takes 64K, no big deal even on a PDA,
 * especially because it can be pre-initialized an put into a ROM!),
 * otherwhise we use a table of logarithms.
 * In any case the macro gf_mul(x,y) takes care of multiplications.
 */

static gf gf_exp[2*GF_SIZE];    /* index->poly form conversion table    */
static int gf_log[GF_SIZE + 1]; /* Poly->index form conversion table    */
static gf inverse[GF_SIZE+1];   /* inverse of field elem.       */
                /* inv[\alpha**i]=\alpha**(GF_SIZE-i-1) */

/*
 * modnn(x) computes x % GF_SIZE, where GF_SIZE is 2**GF_BITS - 1,
 * without a slow divide.
 */
static inline gf modnn(int x)
{
    while (x >= GF_SIZE) {
    x -= GF_SIZE;
    x = (x >> GF_BITS) + (x & GF_SIZE);
    }
    return x;
}

#define SWAP(a,b,t) {t tmp; tmp=a; a=b; b=tmp;}

/*
 * gf_mul(x,y) multiplies two numbers. If GF_BITS<=8, it is much
 * faster to use a multiplication table.
 *
 * USE_GF_MULC, GF_MULC0(c) and GF_ADDMULC(x) can be used when multiplying
 * many numbers by the same constant. In this case the first
 * call sets the constant, and others perform the multiplications.
 * A value related to the multiplication is held in a local variable
 * declared with USE_GF_MULC . See usage in addmul1().
 */
static gf gf_mul_table[(GF_SIZE + 1)*(GF_SIZE + 1)]
#ifdef WINDOWS
__attribute__((aligned (16)))
#else
__attribute__((aligned (256)))
#endif
;

#define gf_mul(x,y) gf_mul_table[(x<<8)+y]

#define USE_GF_MULC register gf * __gf_mulc_
#define GF_MULC0(c) __gf_mulc_ = &gf_mul_table[(c)<<8]
#define GF_ADDMULC(dst, x) dst ^= __gf_mulc_[x]
#define GF_MULC(dst, x) dst = __gf_mulc_[x]

static void init_mul_table(void)
{
    int i, j;
    for (i=0; i< GF_SIZE+1; i++)
        for (j=0; j< GF_SIZE+1; j++)
            gf_mul_table[(i<<8)+j] = gf_exp[modnn(gf_log[i] + gf_log[j]) ];

    for (j=0; j< GF_SIZE+1; j++)
        gf_mul_table[j] = gf_mul_table[j<<8] = 0;
}

/*
 * Generate GF(2**m) from the irreducible polynomial p(X) in p[0]..p[m]
 * Lookup tables:
 *     index->polynomial form       gf_exp[] contains j= \alpha^i;
 *     polynomial form -> index form    gf_log[ j = \alpha^i ] = i
 * \alpha=x is the primitive element of GF(2^m)
 *
 * For efficiency, gf_exp[] has size 2*GF_SIZE, so that a simple
 * multiplication of two numbers can be resolved without calling modnn
 */

/*
 * initialize the data structures used for computations in GF.
 */
static void generate_gf(void)
{
    int i;
    gf mask;
    char *Pp =  allPp[GF_BITS];

    mask = 1;   /* x ** 0 = 1 */
    gf_exp[GF_BITS] = 0; /* will be updated at the end of the 1st loop */
    /*
     * first, generate the (polynomial representation of) powers of \alpha,
     * which are stored in gf_exp[i] = \alpha ** i .
     * At the same time build gf_log[gf_exp[i]] = i .
     * The first GF_BITS powers are simply bits shifted to the left.
     */
    for (i = 0; i < GF_BITS; i++, mask <<= 1 ) {
        gf_exp[i] = mask;
        gf_log[gf_exp[i]] = i;
        /*
         * If Pp[i] == 1 then \alpha ** i occurs in poly-repr
         * gf_exp[GF_BITS] = \alpha ** GF_BITS
         */
        if ( Pp[i] == '1' )
            gf_exp[GF_BITS] ^= mask;
    }
    /*
     * now gf_exp[GF_BITS] = \alpha ** GF_BITS is complete, so can als
     * compute its inverse.
     */
    gf_log[gf_exp[GF_BITS]] = GF_BITS;
    /*
     * Poly-repr of \alpha ** (i+1) is given by poly-repr of
     * \alpha ** i shifted left one-bit and accounting for any
     * \alpha ** GF_BITS term that may occur when poly-repr of
     * \alpha ** i is shifted.
     */
    mask = 1 << (GF_BITS - 1 );
    for (i = GF_BITS + 1; i < GF_SIZE; i++) {
        if (gf_exp[i - 1] >= mask)
            gf_exp[i] = gf_exp[GF_BITS] ^ ((gf_exp[i - 1] ^ mask) << 1);
        else
            gf_exp[i] = gf_exp[i - 1] << 1;
        gf_log[gf_exp[i]] = i;
    }
    /*
     * log(0) is not defined, so use a special value
     */
    gf_log[0] = GF_SIZE;
    /* set the extended gf_exp values for fast multiply */
    for (i = 0; i < GF_SIZE; i++)
        gf_exp[i + GF_SIZE] = gf_exp[i];

    /*
     * again special cases. 0 has no inverse. This used to
     * be initialized to GF_SIZE, but it should make no difference
     * since noone is supposed to read from here.
     */
    inverse[0] = 0;
    inverse[1] = 1;
    for (i=2; i<=GF_SIZE; i++)
        inverse[i] = gf_exp[GF_SIZE-gf_log[i]];
}

/*
 * Various linear algebra operations that i use often.
 */

/*
 * addmul() computes dst[] = dst[] + c * src[]
 * This is used often, so better optimize it! Currently the loop is
 * unrolled 16 times, a good value for 486 and pentium-class machines.
 * The case c=0 is also optimized, whereas c=1 is not. These
 * calls are unfrequent in my typical apps so I did not bother.
 *
 * Note that gcc on
 */
#if 0
#define addmul(dst, src, c, sz, dst_max, src_max) \
    if (c != 0) addmul1(dst, src, c, sz, dst_max, src_max)
#endif

static void slow_addmul1(gf *dst1, gf *src1, gf c, int64_t sz, int64_t dst_max, int64_t src_max)
{
    USE_GF_MULC;
    register gf *dst = dst1, *src = src1;
    int64_t low_max = dst_max < src_max ? dst_max : src_max;
    int64_t pos = 0;
    gf *lim = &dst[low_max];

    GF_MULC0(c);

    for (; dst < lim; dst++, src++ ) {
        if (pos < src_max && pos < dst_max) {
            GF_ADDMULC( *dst , *src );
        } else if (pos < dst_max) {
            /* assume zero when past the max */
            GF_ADDMULC( *dst , 0 );
        }
        pos += 1;
    }
}

# define addmul1 slow_addmul1

static void addmul(gf *dst, gf *src, gf c, int64_t sz, int64_t dst_max, int64_t src_max)
{
    if (c != 0) addmul1(dst, src, c, sz, dst_max, src_max);
}

/*
 * mul() computes dst[] = c * src[]
 * This is used often, so better optimize it! Currently the loop is
 * unrolled 16 times, a good value for 486 and pentium-class machines.
 * The case c=0 is also optimized, whereas c=1 is not. These
 * calls are unfrequent in my typical apps so I did not bother.
 *
 * Note that gcc on
 */
#if 0
#define mul(dst, src, c, sz, dst_max, src_max) \
    do { if (c != 0) mul1(dst, src, c, sz, dst_max, src_max); else memset(dst, 0, c); } while(0)
#endif

static void slow_mul1(gf *dst1, gf *src1, gf c, int64_t sz, int64_t dst_max, int64_t src_max)
{
    USE_GF_MULC;
    register gf *dst = dst1, *src = src1;
    int64_t low_max = dst_max < src_max ? dst_max : src_max;
    int64_t pos = 0;
    gf *lim = &dst[low_max];

    GF_MULC0(c);

    for (; dst < lim; dst++, src++ ) {
        if (pos < src_max && pos < dst_max) {
            GF_MULC( *dst , *src );
        } else if (pos < dst_max) {
            /* assume zero when past the max */
            GF_MULC( *dst , 0 );
        }
        pos += 1;
    }
}

# define mul1 slow_mul1

static inline void mul(gf *dst, gf *src, gf c, int64_t sz, int64_t dst_max, int64_t src_max)
{
    if (c != 0) mul1(dst, src, c, sz, dst_max, src_max); else memset(dst, 0, c);
}

/*
 * invert_mat() takes a matrix and produces its inverse
 * k is the size of the matrix.
 * (Gauss-Jordan, adapted from Numerical Recipes in C)
 * Return non-zero if singular.
 */
DEB( int pivloops=0; int pivswaps=0; /* diagnostic */)
static int invert_mat(gf *src, int k)
{
    gf c, *p;
    int irow, icol, row, col, i, ix;

    int error = 1;
    int indxc[k];
    int indxr[k];
    int ipiv[k];
    gf id_row[k];

    memset(id_row, 0, k*sizeof(gf));
    DEB( pivloops=0; pivswaps=0; /* diagnostic */ )
        /*
         * ipiv marks elements already used as pivots.
         */
        for (i = 0; i < k; i++)
            ipiv[i] = 0;

    for (col = 0; col < k; col++) {
        gf *pivot_row;
        /*
         * Zeroing column 'col', look for a non-zero element.
         * First try on the diagonal, if it fails, look elsewhere.
         */
        irow = icol = -1;
        if (ipiv[col] != 1 && src[col*k + col] != 0) {
            irow = col;
            icol = col;
            goto found_piv;
        }
        for (row = 0; row < k; row++) {
            if (ipiv[row] != 1) {
                for (ix = 0; ix < k; ix++) {
                    DEB( pivloops++; )
                        if (ipiv[ix] == 0) {
                            if (src[row*k + ix] != 0) {
                                irow = row;
                                icol = ix;
                                goto found_piv;
                            }
                        } else if (ipiv[ix] > 1) {
                            fprintf(stderr, "singular matrix\n");
                            goto fail;
                        }
                }
            }
        }
        if (icol == -1) {
            fprintf(stderr, "XXX pivot not found!\n");
            goto fail;
        }
 found_piv:
        ++(ipiv[icol]);
        /*
         * swap rows irow and icol, so afterwards the diagonal
         * element will be correct. Rarely done, not worth
         * optimizing.
         */
        if (irow != icol) {
            for (ix = 0; ix < k; ix++ ) {
                SWAP( src[irow*k + ix], src[icol*k + ix], gf);
            }
        }
        indxr[col] = irow;
        indxc[col] = icol;
        pivot_row = &src[icol*k];
        c = pivot_row[icol];
        if (c == 0) {
            fprintf(stderr, "singular matrix 2\n");
            goto fail;
        }
        if (c != 1 ) { /* otherwhise this is a NOP */
            /*
             * this is done often , but optimizing is not so
             * fruitful, at least in the obvious ways (unrolling)
             */
            DEB( pivswaps++; )
                c = inverse[ c ];
            pivot_row[icol] = 1;
            for (ix = 0; ix < k; ix++ )
                pivot_row[ix] = gf_mul(c, pivot_row[ix] );
        }
        /*
         * from all rows, remove multiples of the selected row
         * to zero the relevant entry (in fact, the entry is not zero
         * because we know it must be zero).
         * (Here, if we know that the pivot_row is the identity,
         * we can optimize the addmul).
         */
        id_row[icol] = 1;
        if (memcmp(pivot_row, id_row, k*sizeof(gf)) != 0) {
            for (p = src, ix = 0; ix < k; ix++, p += k ) {
                if (ix != icol) {
                    c = p[icol];
                    p[icol] = 0;
                    addmul(p, pivot_row, c, k, k, k);
                }
            }
        }
        id_row[icol] = 0;
    } /* done all columns */
    for (col = k-1; col >= 0; col-- ) {
        if (indxr[col] <0 || indxr[col] >= k)
            fprintf(stderr, "AARGH, indxr[col] %d\n", indxr[col]);
        else if (indxc[col] <0 || indxc[col] >= k)
            fprintf(stderr, "AARGH, indxc[col] %d\n", indxc[col]);
        else
            if (indxr[col] != indxc[col] ) {
                for (row = 0; row < k; row++ ) {
                    SWAP( src[row*k + indxr[col]], src[row*k + indxc[col]], gf);
                }
            }
    }
    error = 0;
fail:
    return error;
}

static int fec_initialized = 0;

void fec_init(void)
{
    TICK(ticks[0]);
    generate_gf();
    TOCK(ticks[0]);
    DDB(fprintf(stderr, "generate_gf took %ldus\n", ticks[0]);)
    TICK(ticks[0]);
    init_mul_table();
    TOCK(ticks[0]);
    DDB(fprintf(stderr, "init_mul_table took %ldus\n", ticks[0]);)
    fec_initialized = 1;
}


#ifdef PROFILE
static long long rdtsc(void)
{
    unsigned long low, hi;
    asm volatile ("rdtsc" : "=d" (hi), "=a" (low));
    return ( (((long long)hi) << 32) | ((long long) low));
}

void print_matrix1(gf* matrix, int nrows, int ncols)
{
    int i, j;
    printf("matrix (%d,%d):\n", nrows, ncols);
    for(i = 0; i < nrows; i++) {
        for(j = 0; j < ncols; j++) {
            printf("%6d ", matrix[i*ncols + j]);
        }
        printf("\n");
    }
}

void print_matrix2(gf** matrix, int nrows, int ncols)
{
    int i, j;
    printf("matrix (%d,%d):\n", nrows, ncols);
    for(i = 0; i < nrows; i++) {
        for(j = 0; j < ncols; j++) {
            printf("%6d ", matrix[i][j]);
        }
        printf("\n");
    }
}

#endif

/* y = a**n */
static gf galExp(gf a, gf n)
{
    int logA;
    int logResult;
    if(0 == n) {
        return 1;
    }
    if(0 == a) {
        return 0;
    }
    logA = gf_log[a];
    logResult = logA * n;
    while(logResult >= 255) {
        logResult -= 255;
    }

    return gf_exp[logResult];
}

static inline gf galMultiply(gf a, gf b)
{
    return gf_mul_table[ ((int)a << 8) + (int)b ];
}

static gf* vandermonde(int nrows, int ncols)
{
    int row, col, ptr;
    gf* matrix = (gf*)RS_MALLOC(nrows * ncols);
    if(NULL != matrix) {
        ptr = 0;
        for(row = 0; row < nrows; row++) {
            for(col = 0; col < ncols; col++) {
                matrix[ptr++] = galExp((gf)row, (gf)col);
            }
        }
    }

    return matrix;
}

/*
 * Not check for input params
 * */
static gf* sub_matrix(gf* matrix, int rmin, int cmin, int rmax, int cmax,
                      int nrows, int ncols)
{
    int i, j, ptr = 0;
    gf* new_m = (gf*)RS_MALLOC( (rmax-rmin) * (cmax-cmin) );
    if(NULL != new_m) {
        for(i = rmin; i < rmax; i++) {
            for(j = cmin; j < cmax; j++) {
                new_m[ptr++] = matrix[i*ncols + j];
            }
        }
    }

    return new_m;
}

/* y = a.dot(b) */
static gf* multiply1(gf *a, int ar, int ac, gf *b, int br, int bc)
{
    gf *new_m, tg;
    int r, c, i, ptr = 0;

    assert(ac == br);
    new_m = (gf*)RS_CALLOC(1, ar*bc);
    if(NULL != new_m) {

        /* this multiply is slow */
        for(r = 0; r < ar; r++) {
            for(c = 0; c < bc; c++) {
                tg = 0;
                for(i = 0; i < ac; i++) {
                    /* tg ^= gf_mul_table[ ((int)a[r*ac+i] << 8) + (int)b[i*bc+c] ]; */
                    tg ^= galMultiply(a[r*ac+i], b[i*bc+c]);
                }

                new_m[ptr++] = tg;
            }
        }

    }

    return new_m;
}

/* copy from golang rs version */
static inline int code_some_shards(gf* matrixRows, gf** inputs, gf** outputs,
                                   int dataShards, int outputCount, int byteCount,
                                   uint64_t *inputsMax, uint64_t * outputsMax)
{
    gf* in;
    int iRow, c;
    for(c = 0; c < dataShards; c++) {
        in = inputs[c];
        for(iRow = 0; iRow < outputCount; iRow++) {
            if(0 == c) {
                mul(outputs[iRow], in, matrixRows[iRow*dataShards+c], byteCount,
                    outputsMax[iRow], inputsMax[c]);
            } else {
                addmul(outputs[iRow], in, matrixRows[iRow*dataShards+c], byteCount,
                       outputsMax[iRow], inputsMax[c]);
            }
        }
    }

    return 0;
}

reed_solomon* reed_solomon_new(int data_shards, int parity_shards)
{
    gf* vm = NULL;
    gf* top = NULL;
    int err = 0;
    reed_solomon* rs = NULL;

    /* MUST use fec_init once time first */
    assert(fec_initialized);

    do {
        rs = RS_MALLOC(sizeof(reed_solomon));
        if(NULL == rs) {
            return NULL;
        }
        rs->data_shards = data_shards;
        rs->parity_shards = parity_shards;
        rs->shards = (data_shards + parity_shards);
        rs->m = NULL;
        rs->parity = NULL;

        if(rs->shards > DATA_SHARDS_MAX || data_shards <= 0 || parity_shards <= 0) {
            err = 1;
            break;
        }

        vm = vandermonde(rs->shards, rs->data_shards);
        if(NULL == vm) {
            err = 2;
            break;
        }

        top = sub_matrix(vm, 0, 0, data_shards, data_shards, rs->shards, data_shards);
        if(NULL == top) {
            err = 3;
            break;
        }

        err = invert_mat(top, data_shards);
        assert(0 == err);

        rs->m = multiply1(vm, rs->shards, data_shards, top, data_shards, data_shards);
        if(NULL == rs->m) {
            err = 4;
            break;
        }

        rs->parity = sub_matrix(rs->m, data_shards, 0, rs->shards, data_shards, rs->shards, data_shards);
        if(NULL == rs->parity) {
            err = 5;
            break;
        }

        RS_FREE(vm);
        RS_FREE(top);
        vm = NULL;
        top = NULL;
        return rs;

    } while(0);

    fprintf(stderr, "err=%d\n", err);
    if(NULL != vm) {
        RS_FREE(vm);
    }
    if(NULL != top) {
        RS_FREE(top);
    }
    if(NULL != rs) {
        if(NULL != rs->m) {
            RS_FREE(rs->m);
        }
        if(NULL != rs->parity) {
            RS_FREE(rs->parity);
        }
        RS_FREE(rs);
    }

    return NULL;
}

void reed_solomon_release(reed_solomon* rs)
{
    if(NULL != rs) {
        if(NULL != rs->m) {
            RS_FREE(rs->m);
        }
        if(NULL != rs->parity) {
            RS_FREE(rs->parity);
        }
        RS_FREE(rs);
    }
}

int reed_solomon_encode(reed_solomon* rs,
                        uint8_t** data_blocks,
                        uint8_t** fec_blocks,
                        uint64_t block_size,
                        uint64_t total_bytes)
{
    assert(NULL != rs && NULL != rs->parity);

    uint64_t data_blocks_max[rs->data_shards];
    uint64_t fec_blocks_max[rs->parity_shards];

    int c = 0;

    // Calculate the max for each shard based on the total bytes
    // the last shard may be less than the shard size
    for (c = 0; c < rs->data_shards; c++) {
        uint64_t bytes_remaining = total_bytes - c * block_size;
        uint64_t max = block_size;
        if (bytes_remaining < block_size) {
            max = bytes_remaining;
        }
        data_blocks_max[c] = max;
    }

    // All of the parity shards will be the block size
    for (c = 0; c < rs->parity_shards; c++) {
        fec_blocks_max[c] = block_size;
    }

    return code_some_shards(rs->parity, data_blocks, fec_blocks,
                            rs->data_shards, rs->parity_shards, block_size,
                            data_blocks_max, fec_blocks_max);
}

int reed_solomon_decode(reed_solomon* rs,
                        uint8_t **data_blocks,
                        uint64_t block_size,
                        uint8_t **dec_fec_blocks,
                        unsigned int *fec_block_nos,
                        unsigned int *erased_blocks,
                        int nr_fec_blocks,
                        uint64_t total_bytes)
{
    /* use stack instead of malloc, define a small number of DATA_SHARDS_MAX to save memory */
    gf dataDecodeMatrix[DATA_SHARDS_MAX*DATA_SHARDS_MAX];
    uint8_t* subShards[DATA_SHARDS_MAX];
    uint64_t subShardsMax[DATA_SHARDS_MAX];
    uint8_t* outputs[DATA_SHARDS_MAX];
    uint64_t outputsMax[DATA_SHARDS_MAX];
    gf* m = rs->m;
    int i, j, c, swap, subMatrixRow, dataShards, nos, nshards;

    /* the erased_blocks should always sorted
     * if sorted, nr_fec_blocks times to check it
     * if not, sort it here
     * */
    for(i = 0; i < nr_fec_blocks; i++) {
        swap = 0;
        for(j = i+1; j < nr_fec_blocks; j++) {
            if(erased_blocks[i] > erased_blocks[j]) {
                /* the prefix is bigger than the following, swap */
                c = erased_blocks[i];
                erased_blocks[i] = erased_blocks[j];
                erased_blocks[j] = c;

                swap = 1;
            }
        }
        if(!swap) {
            //already sorted or sorted ok
            break;
        }
    }

    j = 0;
    subMatrixRow = 0;
    nos = 0;
    nshards = 0;
    dataShards = rs->data_shards;

    for(i = 0; i < dataShards; i++) {

        // Determine if the shard has less than block size
        uint64_t remaining = total_bytes - i * block_size;
        uint64_t max = block_size;
        if (remaining < block_size) {
            max = remaining;
        }

        if(j < nr_fec_blocks && i == erased_blocks[j]) {
            //ignore the invalid block
            j++;
        } else {
            /* this row is ok */
            for(c = 0; c < dataShards; c++) {
                dataDecodeMatrix[subMatrixRow*dataShards + c] = m[i*dataShards + c];
            }
            subShards[subMatrixRow] = data_blocks[i];
            subShardsMax[subMatrixRow] = max;
            subMatrixRow++;
        }
    }

    for(i = 0; i < nr_fec_blocks && subMatrixRow < dataShards; i++) {
        subShards[subMatrixRow] = dec_fec_blocks[i];
        subShardsMax[subMatrixRow] = block_size; /* all fec shards have block_size */
        j = dataShards + fec_block_nos[i];
        for(c = 0; c < dataShards; c++) {
            dataDecodeMatrix[subMatrixRow*dataShards + c] = m[j*dataShards + c]; //use spefic pos of original fec_blocks
        }
        subMatrixRow++;
    }

    if(subMatrixRow < dataShards) {
        //cannot correct
        return -1;
    }

    invert_mat(dataDecodeMatrix, dataShards);

    for(i = 0; i < nr_fec_blocks; i++) {
        j = erased_blocks[i];

        // Determine if the shard has less than block size
        uint64_t remaining = total_bytes - j * block_size;
        uint64_t max = block_size;
        if (remaining < block_size) {
            max = remaining;
        }

        outputs[i] = data_blocks[j];
        outputsMax[i] = max;
        memmove(dataDecodeMatrix+i*dataShards, dataDecodeMatrix+j*dataShards, dataShards);
    }

    return code_some_shards(dataDecodeMatrix, subShards, outputs,
                            dataShards, nr_fec_blocks, block_size,
                            subShardsMax, outputsMax);
}

int reed_solomon_encode2(reed_solomon* rs, uint8_t** data_blocks,
                         uint8_t** fec_blocks, int nr_shards, uint64_t block_size,
                         uint64_t total_bytes)
{
    int i, ds = rs->data_shards, ps = rs->parity_shards, ss = rs->shards;
    i = nr_shards / ss;

    for(i = 0; i < nr_shards; i += ss) {
        reed_solomon_encode(rs, data_blocks, fec_blocks, block_size, total_bytes);
        data_blocks += ds;
        fec_blocks += ps;
    }
    return 0;
}

int reed_solomon_reconstruct(reed_solomon* rs,
                             uint8_t** data_blocks,
                             uint8_t** fec_blocks,
                             uint8_t* marks,
                             int nr_shards,
                             uint64_t block_size,
                             uint64_t total_bytes)
{
    uint8_t *dec_fec_blocks[DATA_SHARDS_MAX];
    unsigned int fec_block_nos[DATA_SHARDS_MAX];
    unsigned int erased_blocks[DATA_SHARDS_MAX];
    uint8_t* fec_marks;
    int i, j, dn, pn, n;
    int ds = rs->data_shards;
    int ps = rs->parity_shards;
    int err = 0;

    n = nr_shards / rs->shards;
    fec_marks = marks + n*ds; //after all data, is't fec marks

    for(j = 0; j < n; j++) {
        dn = 0;
        for(i = 0; i < ds; i++) {
            if(marks[i]) {
                //errors
                erased_blocks[dn++] = i;
            }
        }
        if(dn > 0) {
            pn = 0;
            for(i = 0; i < ps && pn < dn; i++) {
                if(!fec_marks[i]) {
                    //got valid fec row
                    fec_block_nos[pn] = i;
                    dec_fec_blocks[pn] = fec_blocks[i];
                    pn++;
                }
            }

            if(dn == pn) {
                reed_solomon_decode(rs,
                                    data_blocks,
                                    block_size,
                                    dec_fec_blocks,
                                    fec_block_nos,
                                    erased_blocks,
                                    dn,
                                    total_bytes);
            } else {
                //error but we continue
                err = -1;
            }
        }
        data_blocks += ds;
        marks += ds;
        fec_blocks += ps;
        fec_marks += ps;
    }

    return err;
}
