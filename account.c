// this is preposterous, I want to speak with the manager
#include "block.c"
#define F(B, C, D, E) B ^ C ^ D ^ E
#define G(B, C, D, E) ((B & C) | (~B & D) | (C & E))
#define H(B, C, D) (B | ~C) ^ D
#define I(B, C, D) (B & D) | (C & ~D)
#define J(B, C, D) B ^ (C | ~D)
#define TWO_AT_32 1ULL << 32
#define MAINNET_VERSION 0x00

struct account
{
    char *name;
    uint8_t *priv_key, *pub_key;
    double balance;
};

uint32_t leftrotation(uint32_t x, uint32_t n)
{
    return ((x << n) | (x >> (32 - n)));
}

static uint32_t k1[] = {0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E, 0x00000000};
static uint32_t k2[] = {0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000, 0x00000000};

static const uint8_t s1[80] = {
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15,
    7, 11, 13, 14, 15, 12, 9, 5, 6, 10, 11, 13,
    15, 7, 12, 9, 11, 13, 14, 15, 12, 7, 10, 15,
    13, 6, 12, 9, 11, 13, 14, 15, 12, 9, 7, 14,
    13, 6, 12, 11, 10, 14, 12, 15, 9, 7, 11, 12,
    13, 14, 15, 10, 11, 14, 12, 7, 13, 14, 11, 9};

static const uint8_t s2[80] = {
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15,
    7, 11, 13, 14, 15, 12, 9, 5, 6, 10, 11, 13,
    15, 7, 12, 9, 11, 13, 14, 15, 12, 7, 10, 15,
    13, 6, 12, 9, 11, 13, 14, 15, 12, 9, 7, 14,
    13, 6, 12, 11, 10, 14, 12, 15, 9, 7, 11, 12,
    13, 14, 15, 10, 11, 14, 12, 7, 13, 14, 11, 9};

void ripemd160(uint8_t *input, size_t size, uint8_t out[20])
{
    uint8_t *data = input;
    size_t sz = size, alloc = 0; // to know if memory was allocated
    if (size % 64 != 0)
    {
        // padding
        sz = size + 64 - (size % 64);
        data = malloc(size + 64 - (size % 64));
        memcpy(data, input, size);
        data[size] = 0x80;
        memset(&data[size], 0, sz - size);
        alloc = 1;
    }

    uint32_t A = 0x67452301, B = 0xEFCDAB89, C = 0x98BADCFE, D = 0x10325476, E = 0xC3D2E1F0;
    uint32_t *W;
    uint32_t AL = A, AR = A;
    uint32_t BL = B, BR = B;
    uint32_t CL = C, CR = C;
    uint32_t DL = D, DR = D;
    uint32_t EL = E, ER = E, T;
    for (int i = 0; i < sz; i += 64)
    {
        W = (uint32_t *)(input + i);
        for (int i = 0; i < 79; i++)
        {
            T = (AL + F(i, BL, CL, DL) + W[k1[i]] + k1[i]);
            T = leftrotation(T, s1[i]) + EL;
            AL = EL, EL = DL, DL = leftrotation(CL, 10), CL = BL, BL = T;

            T = (AR + G(i, BR, CR, DR) + W[k2[i]] + k2[i]);
            T = leftrotation(T, s2[i]) + ER;
            AR = ER, ER = DR, DR = leftrotation(CR, 10), CR = BR, BR = T;
        }
    }

    T = (A + CL + DR) % TWO_AT_32;
    A = (B + DL + ER) % TWO_AT_32;
    B = (C + EL + AR) % TWO_AT_32;
    C = (D + AL + BR) % TWO_AT_32;
    D = (E + BL + CR) % TWO_AT_32;
    E = T;

    uint32_t x[] = {A, B, C, D, E};
    memcpy(out, x, 20); // 20 bytes = 160 bits
    if (alloc)
        free(data);
}

// TO DO: Generate Public Key
void generate_pkey()
{
    uint8_t data[65];
    data[0] = 0x04;
}

void generate_addr(uint8_t* public_key, uint8_t* result)
{
    uint32_t data[8], data2[8];
    uint8_t out[21], out2[21];

    sha256(public_key, 65, data);
    ripemd160((uint8_t*)data, 32, out + 1);

    out[0] = MAINNET_VERSION; // append version

    sha256(data, 21, data2);
    memset(out, 0, 32);
    sha256(data2, 32, out2);

    memcpy(result, out, 21);
    memcpy(result + 21, out2, 4);
}