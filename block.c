#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <memory.h>
#define Ch(e, f, g)  (e & f) ^ ((~e) & g)
#define Maj(a, b, c) (a & b) ^ (a & c) ^ (b & c)
#define SYSTEM_ID 0xC1C7E00
#define MAX_TRANSACTION_AMOUNT 200000000 // can be modified later

struct transaction
{
    uint64_t from, to;
    uint32_t nonce;
    uint32_t amount;
    uint64_t id;
};

static uint32_t crypto_rand()
{
    return 0U;
}

struct ledger
{
    struct transactions** list;
    size_t size, cap;
} local_ledger;
uint64_t last_generated_id;

struct transaction* init_transaction(uint64_t from, uint64_t to, uint32_t amount)
{
    struct transaction* t = malloc(sizeof(struct transaction));
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
        ledger->list = realloc(ledger->list, sizeof(struct ledger*) * (ledger->cap + 10));
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

struct block
{
    uint8_t* data;
    uint32_t sha[8], prev_sha[8];
    uint32_t size; // idk what is this 
    uint32_t last; // initially set to 0, represents the chunks that were hashed
    double reward; // the reward, when halving block->reward /= 2 
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

void sha256(uint8_t* input, size_t size, uint32_t* output)
{
    uint8_t* data = input;
    size_t sz = size, alloc = 0; // to know if memory was allocated
    if(size % 64 != 0)
    {
        // padding
        sz = size + 64 - (size % 64);
        data = malloc(size + 64 - (size % 64));
        memcpy(data, input, size);
        data[size + 1] = 1;
        memset(&data[size], 0, sz - size - 1);
        alloc = 1;
    }

    uint32_t* W = realloc(data, 64 * 32);
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

    if(alloc) free(data);
    free(W);
}

uint8_t* grab_64b(struct block* b)
{
    b->last += 64;
    return &b->data[b->last - 64];
}

void hash_64b(struct block* b, uint32_t out[8])
{
    uint8_t* data = grab_64b(b);
    sha256(data, 64, out);
}

void hash_block(struct block* b)
{
    sha256(b->data, b->size, b->sha);
}

int hash_and_compare(char* str1, uint32_t hash[8])
{
    uint32_t hash2[8];
    sha256(str1, strlen(str1), hash2);
    return (memcmp(hash, hash2, 8) == 0);
}

struct block* init_block_str(char* str) // with a message, not binary data
{
    struct block* b = malloc(sizeof(struct block));
    b->data = str;
    b->size = strlen(str);
    b->reward = 0; // to be set by the SYSTEM
    b->last = 0;
    return b;
}

int release_block(struct block* b)
{
    if(b->last != b->size) // if not finished
        return -1;

    b->reward = 0;
    free(b);
}

void free_block(struct block* b)
{
    free(b);
}

void save_block(struct block* b, char* filename)
{
    FILE* fp = fopen(filename, "w+");
    fwrite(&b->last, sizeof(struct block) - sizeof(uint8_t*), 1, fp);
    fwrite(b->data, b->size, 1, fp);
    fclose(fp);
}

void print_block_hash(struct block* b)
{
    for(int i = 0;i < 8;i++)
        printf("%08x", b->sha[i]);
}

void reward_block(struct block* b, uint64_t user)
{
    struct transaction* t = init_transaction(SYSTEM_ID, user, b->reward);
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
    b.blocks = malloc(sizeof(struct block) * num_blocks);
    b.size = num_blocks;
    b.cap = 0;
    return b;
}

struct block* prev_block(struct blockchain chain, struct block* b)
{
    return find_block(chain, b->prev_sha);
}

void add_block(struct blockchain* chain, struct block* b)
{
    if(b == NULL || chain == NULL || chain->blocks == NULL) return;
    if(chain->cap > 0)
        memcpy(b->prev_sha, chain->blocks[chain->cap - 1].sha, 8 * sizeof(uint32_t));
    else 
        memset(b->prev_sha, 0, 8 * sizeof(uint32_t)); // sets it to 0
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

// TO BE CHANGED LATER!
struct merkle
{
    size_t size;
    struct transaction t[];
};

// Create a Merkle node from a ledger containing all transactions
struct merkle* merkle_ledger(struct ledger* l, size_t start, size_t end) {
    if (start > end || start >= l->size) return NULL;
    if (end >= l->size) end = l->size - 1; // Ensure 'end' does not exceed ledger size

    size_t num_transactions = end - start + 1;
    struct merkle* m = malloc(sizeof(struct merkle) + num_transactions * sizeof(struct transaction));
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
    if(!valid_transaction(&t)) return -1; // cannot add invalid transactions here
    m->t[m->size++] = t;
    return 0;
}

void merkle_root(struct merkle* m, uint32_t sha[8])
{
    sha256((uint8_t*)m->t, m->size * sizeof(struct transaction), sha);
}

int main()
{
    struct blockchain chain = create_chain(5);
    add_block(&chain, init_block_str("Wow"));
    add_block(&chain, init_block_str("It is"));
    add_block(&chain, init_block_str("nice"));

    return 0;
}