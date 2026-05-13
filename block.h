#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <memory.h>
#include <assert.h>
#include <time.h>
#define Ch(e, f, g)  (e & f) ^ ((~e) & g)
#define Maj(a, b, c) (a & b) ^ (a & c) ^ (b & c)
#define SYSTEM_ID 0xC1C7E00
#define MAX_TRANSACTION_AMOUNT 200000000 // can be modified later
#define MAKE_VERSION(a, b, c) (a << 16) | (b << 8) | c

// Error Codes for SHA256
#define SHA256_SUCCESS 0
#define SHA256_COULD_NOT_ALLOCATE_MEMORY -1

struct transaction
{
    uint64_t from, to;
    uint32_t nonce;
    uint32_t amount;
    uint64_t id;
    uint8_t* data;
};

double block_reward = 12.0f;

typedef struct { uint64_t state;  uint64_t inc; } pcg32_random_t; // using the PCG 32 from https://www.pcg-random.org/
pcg32_random_t* rng;

static uint32_t crypto_rand()
{
    uint64_t oldstate = rng->state;
    rng->state = oldstate * 6364136223846793005ULL + (rng->inc|1);
    uint32_t xorshifted = ((oldstate >> 18u) ^ oldstate) >> 27u;
    uint32_t rot = oldstate >> 59u;
    return (xorshifted >> rot) | (xorshifted << ((-rot) & 31));
}

void crypto_setup()
{
    rng = (pcg32_random_t*)malloc(sizeof(pcg32_random_t));
    rng->state = (uint64_t)time(NULL) ^ (uintptr_t)&rng;
    rng->inc = (uint64_t)time(NULL) ^ (uintptr_t)&rng;
}

struct ledger
{
    struct transaction** list;
    size_t size, cap;
} local_ledger;
uint64_t last_generated_id;

struct merkle
{
    size_t size;
    struct transaction t[];
};

size_t generate_id()
{
    uint64_t id = rand() + last_generated_id++;
    last_generated_id = id;
    return id;
}

struct transaction* init_transaction(uint64_t from, uint64_t to, uint32_t amount)
{
    struct transaction* t = (struct transaction*)malloc(sizeof(struct transaction));
    if(t == NULL) return NULL;

    if(from == 0) t->from = SYSTEM_ID;
    else t->from = from;
    t->nonce = crypto_rand(); // to be replaced
    t->to = to;
    t->amount = amount;
    t->id = generate_id();
    return t;
}

void add_transaction(struct ledger* ledger, struct transaction* t)
{
    if(ledger->size + 1 == ledger->cap) {
        void* original = (void*)ledger->list;
        ledger->list = (struct transaction**)realloc(ledger->list, sizeof(struct ledger*) * (ledger->cap + 10));
        if(ledger->list == NULL) {
            ledger->list = (struct transaction**)original; // restore original pointer on failure
            return;
        }
        ledger->cap += 10;
    }
    ledger->list[ledger->size++] = t;
}

int valid_transaction(struct transaction* t)
{
    if(t->amount > MAX_TRANSACTION_AMOUNT)
        return -1;

    if(t->id > last_generated_id)
        return -1;

    return 0;
}

struct block_header { 
        uint32_t version;
        uint32_t prev_sha[8];
        uint32_t merkle[8]; 
        uint32_t nonce;
        uint64_t timestamp;
        uint32_t difficulty;
};

struct block
{
    uint32_t sha[8];
    struct block_header header;
    struct {
        size_t size;
        struct transaction t[];
    } data;
};

uint32_t hashes[9] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

uint32_t rightrotate(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

int sha256(uint8_t* input, size_t size, uint32_t* output)
{
    assert(input != NULL && "Input cannot be NULL");
    assert(output != NULL && "Output cannot be NULL");
    assert(size > 0 && "Input size must be greater than 0");

    uint8_t* data = input;
    size_t sz = size, alloc = 0; // to know if memory was allocated
    if(size % 64 != 0)
    {
        // padding
        sz = size + 64 - (size % 64);
        data = (uint8_t*)malloc(sz);
        if(data == NULL) return SHA256_COULD_NOT_ALLOCATE_MEMORY;

        memcpy(data, input, size);
        data[size + 1] = 0x80;
        memset(&data[size], 0, sz - size - 1);
        alloc = 1;
    }

    uint32_t* W = (uint32_t*)realloc(data, 64 * 32);
    if(W == NULL) {
        if(alloc) free(data);
        return SHA256_COULD_NOT_ALLOCATE_MEMORY;
    }

    uint32_t s0, s1, v[8];
    int t;
    for(t = 16;t < 63;t++)
    {
            s0 = rightrotate(W[t-15], 7) ^ rightrotate(W[t-15], 18) ^ (W[t-15] >> 3);
            s1 = rightrotate(W[t-2], 17) ^ rightrotate(W[t-2], 19) ^ (W[t-2] >> 10);
            W[t] = W[t-16] + s0 + W[t-7] + s1;
    }

    memcpy(v, hashes, 8 * 4);
    int T1, T2;
    for(t = 0;t < 64;t++)
    {
            T1 = v[7] + rightrotate(v[4], 6) ^ rightrotate(v[4], 11) ^ rightrotate(v[4], 25) + Ch(v[4], v[5], v[6]) + K[t] + W[t];
            T2 = rightrotate(v[0], 2) ^ rightrotate(v[0], 13) ^ rightrotate(v[0], 22) + Maj(v[0], v[1], v[2]);
            v[7] = v[6], v[6] = v[5], v[5] = v[4]; // circular, yeey
            v[4] = v[3] + T1, v[3] = v[2], v[1] = v[0], v[0] = T1 + T2;
    }
    
    for(int i = 0;i < 8;i++) {
        hashes[i] += v[i];
        output[i] = hashes[i];
    }

    if(alloc) {
        memset(data, 0, sz); 
        free(data);
    }
    
    free(W);

    W = NULL;
    data = NULL;
}

int try_mine_block(struct block* b, uint32_t max_sha[8])
{
    uint32_t data[8];
    b->header.nonce++;
    sha256((uint8_t*)&b->header, sizeof(b->header), data);
    return (memcmp(data, max_sha, 32) < 0);
}

int mine_block(struct block* b, uint32_t max_sha[8]) 
{
    uint32_t data[8];
    do {
        b->header.nonce++;
        if(sha256((uint8_t*)&b->header, sizeof(b->header), data) == SHA256_COULD_NOT_ALLOCATE_MEMORY) {
            fprintf(stderr, "Error: Could not allocate memory for SHA256 computation.\n");
            return -1; // Indicate failure due to memory allocation
        }

        if(sha256((uint8_t*)data, 32, data) == SHA256_COULD_NOT_ALLOCATE_MEMORY) {
            fprintf(stderr, "Error: Could not allocate memory for SHA256 computation.\n");
            return -1; // Indicate failure due to memory allocation
        }

    } while (memcmp(data, max_sha, 32) >= 0);
    
    memcpy(b->sha, data, 32);
    return 1;
}

int validate_sha(struct block* b)
{
    uint32_t data[8];
    sha256((uint8_t*)&b->header, sizeof(b->header), data);
    sha256((uint8_t*)data, 32, data);
    return memcmp(b->sha, data, 32);
}

int hash_and_compare(char* str1, uint32_t hash[8])
{
    uint32_t hash2[8];
    sha256((uint8_t*)str1, strlen(str1), hash2);
    sha256((uint8_t*)hash2, 32, hash2);
    return (memcmp(hash, hash2, 8) == 0);
}

void bits_to_target(uint32_t bits, uint8_t target[32]) {
    memset(target, 0, 32);

    uint32_t exponent = bits >> 24;
    uint32_t mantissa = bits & 0xFFFFFF;

    int idx = 32 - exponent;

    target[idx]     = (mantissa >> 16) & 0xFF;
    target[idx + 1] = (mantissa >> 8) & 0xFF;
    target[idx + 2] = mantissa & 0xFF;
}

struct block* init_block(size_t no_tr) // with a message, not binary data
{
    struct block* b = (struct block*)malloc(sizeof(struct block) + no_tr * sizeof(struct transaction));
    memset(b->sha, 0, 32);
    b->header.nonce = 1;
    b->header.timestamp = time(NULL);
    b->header.version = MAKE_VERSION(1, 1, 0);
    b->header.difficulty = 0x1d00ffff; // to be modified later
}

void free_block(struct block* b)
{
    free(b);
}

void save_block(struct block* b, char* filename)
{
    FILE* fp = fopen(filename, "w+");
    printf("%u %u %u", b->header.nonce, b->header.timestamp, b->header.difficulty);
    for(int i = 0;i < b->data.size;i++)
    {
        fprintf(fp, "%u %u %u %ull", b->data.t[i].amount, b->data.t[i].to, b->data.t[i].from, b->data.t[i].id);
    }
    fclose(fp);
}

void print_block_hash(struct block* b)
{
    for(int i = 0;i < 8;i++)
        printf("%08x", b->sha[i]);
}

void print_hash(uint32_t hash[8], char sep)
{
    for(int i = 0;i < 8;i++)
        printf("%08x%c", hash[i], sep);
}

void reward_block(struct block* b, uint64_t user)
{
    struct transaction* t = init_transaction(SYSTEM_ID, user, block_reward);
    add_transaction(&local_ledger, t);
    free_block(b);
}

struct blockchain
{
    struct block* blocks;
    size_t size, cap;
};

struct block* find_block(struct blockchain blockchain, uint32_t target_sha[8]) {
    for (int i = 0; i < blockchain.size; ++i) {
        if (memcmp(blockchain.blocks[i].sha, target_sha, 8 * sizeof(int)) == 0) {
            return &blockchain.blocks[i];
        }
    }
    return NULL;
}

struct blockchain create_chain(size_t num_blocks) {
    struct blockchain b;
    b.blocks = (struct block*)malloc(sizeof(struct block) * num_blocks);
    b.size = num_blocks;
    b.cap = 0;
    return b;
}

struct block* prev_block(struct blockchain chain, struct block* b)
{
    return find_block(chain, b->header.prev_sha);
}

void add_block(struct blockchain* chain, struct block* b)
{
    if(b == NULL || chain == NULL || chain->blocks == NULL) return;
    if(chain->cap > 0)
        memcpy(b->header.prev_sha, chain->blocks[chain->cap - 1].sha, 8 * sizeof(uint32_t));
    else 
        memset(b->header.prev_sha, 0, 8 * sizeof(uint32_t)); // sets it to 0
    memcpy(&chain->blocks[chain->cap], b, sizeof(struct block));
    chain->cap++;
}

inline struct block* root_block(struct blockchain* b)
{
    if(b == NULL || b->blocks == NULL) return NULL;
    return &b->blocks[0];
}

void free_chain()
{

}

struct merkle* merkle_ledger(struct ledger* l, size_t start, size_t end) {
    if (start > end || start >= l->size) 
        return NULL;
        
    if (end >= l->size) 
        end = l->size - 1; 

    size_t num_transactions = end - start + 1;
    struct merkle* m = (struct merkle*)malloc(sizeof(struct merkle) + num_transactions * sizeof(struct transaction));
    if (!m) return NULL;

    m->size = num_transactions;
    for (size_t i = 0; i < num_transactions; i++) {
        memcpy(&m->t[i], l->list[start + i], sizeof(struct transaction));
    }

    return m;
}

int merkle_add(struct merkle* m, struct transaction t)
{
    if(m == NULL) return -1;
    if(!valid_transaction(&t)) return -1;
    m->t[m->size++] = t;
    return 0;
}

#define MAX_TX 128 // maximum number of transactions in a block, can be modified laters

void merkle_root(struct merkle* m, uint32_t root[8])
{
    uint32_t current[MAX_TX][8];
    uint32_t next[MAX_TX][8];

    size_t n = m->size;

    for (size_t i = 0; i < n; i++) {
        sha256((uint8_t*)&m->t[i], sizeof(struct transaction), current[i]);
        sha256((uint8_t*)current[i], 32, current[i]);
    }

    while (n > 1) {

        if (n % 2 != 0) {
            memcpy(current[n], current[n - 1], 32);
            n++;
        }

        size_t j = 0;

        for (size_t i = 0; i < n; i += 2) {

            uint32_t concat[16];

            memcpy(concat,     current[i],     32);
            memcpy(concat + 8, current[i + 1], 32);

            sha256((uint8_t*)concat, 64, next[j]);
            sha256((uint8_t*)next[j], 32, next[j]);

            j++;
        }

        memcpy(current, next, j * 32);
        n = j;
    }

    memcpy(root, current[0], 32);
}

void merkle_block(struct block* b)
{
    merkle_root((struct merkle*)&b->data, b->header.merkle);
}

struct contract
{
    uint8_t* code; // best if bytecode
    struct {
        uint32_t address[8]; // sha of the block
        void* other;
    } data;
};

void deploy_contract(struct blockchain b, struct contract* c)
{
    struct block* cntb = &b.blocks[b.size];
    memcpy(c->data.address, cntb, 8 * sizeof(uint32_t));
}

struct transaction* get_contract_transaction(struct block* b)
{
    for(int i = 0;i < b->data.size;i++)
        if(b->data.t[i].data != NULL)
            return &b->data.t[i];
}
