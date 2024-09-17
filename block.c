#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <memory.h>
#include <time.h>
#define Ch(e, f, g)  (e & f) ^ ((~e) & g)
#define Maj(a, b, c) (a & b) ^ (a & c) ^ (b & c)
#define SYSTEM_ID 0xC1C7E00
#define MAX_TRANSACTION_AMOUNT 200000000 // can be modified later
#define MAKE_VERSION(a, b, c) (a << 16) | (b << 8) | c

struct transaction
{
    uint64_t from, to;
    uint32_t nonce;
    uint32_t amount;
    uint64_t id;
    uint8_t* data;
};

double block_reward = 12.0f;

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
        sha256((uint8_t*)&b->header, sizeof(b->header), data);
    } while (memcmp(data, max_sha, 32) >= 0);
    
    memcpy(b->sha, data, 32);
    return 1;
}

int validate_sha(struct block* b)
{
    uint32_t data[8];
    sha256((uint8_t*)&b->header, sizeof(b->header), data);
    return memcmp(b->sha, data, 32);
}

int hash_and_compare(char* str1, uint32_t hash[8])
{
    uint32_t hash2[8];
    sha256(str1, strlen(str1), hash2);
    return (memcmp(hash, hash2, 8) == 0);
}

struct block* init_block(size_t no_tr) // with a message, not binary data
{
    struct block* b = malloc(sizeof(struct block) + no_tr * sizeof(struct transaction));
    memset(b->sha, 0, 32);
    b->header.nonce = 1;
    b->header.timestamp = time(NULL);
    b->header.version = MAKE_VERSION(1, 1, 0);
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
    b.blocks = malloc(sizeof(struct block) * num_blocks);
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

void merkle_block(struct block* b)
{
    merkle_root(&b->data, b->header.merkle);
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

/*
int main()
{
    struct block* b = init_block(2);
    uint32_t max_sha[8] = {0x2540001, 0x987556f, 0x1234567, 0x7af0bd1, 0x1999324, 0x81aacd00, 0x9ff990};
    b->data.t[0] =  (struct transaction){.amount = 0.1f, .from = SYSTEM_ID, .to = 0x1ff000};
    b->data.t[1] =  (struct transaction){.amount = 0.05f, .from = SYSTEM_ID, .to = 0x1ea000};
    mine_block(b, max_sha);
    if(!validate_sha(b)) {
        printf("Got wrong sha!");
        print_block_hash(b);
        exit(0);
    }
    print_block_hash(b);
    printf("\nTries: %i", b->header.nonce);
    return 0;
}
*/