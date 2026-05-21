#pragma once
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
#define MAX_TX 128 // maximum number of transactions in a block, can be modified laters

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

typedef struct { uint64_t state;  uint64_t inc; } pcg32_random_t; // using the PCG 32 from https://www.pcg-random.org/

static uint32_t crypto_rand();
void crypto_setup();

struct ledger
{
    struct transaction** list;
    size_t size, cap;
};

struct merkle
{
    size_t size;
    struct transaction t[];
};

size_t generate_id();
struct transaction* init_transaction(uint64_t from, uint64_t to, uint32_t amount);
void add_transaction(struct ledger* ledger, struct transaction* t);
int valid_transaction(struct transaction* t);

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
        struct transaction* t;
    } data;
};

int try_mine_block(struct block* b, uint32_t max_sha[8]);
int mine_block(struct block* b, uint32_t max_sha[8]);
int validate_sha(struct block* b);
int hash_and_compare(char* str1, uint32_t hash[8]);
void bits_to_target(uint32_t bits, uint8_t target[32]);
struct block* init_block(size_t no_tr);
void add_transaction_to_block(struct block* b, struct transaction* t);

void create_reference_block(struct block* b, void* ptr);
void free_block(struct block* b);
void save_block(struct block* b, char* filename);
void print_block_hash(struct block* b);
void print_hash(uint32_t hash[8], char sep);
void reward_block(struct block* b, uint64_t user);

struct blockchain
{
    struct block* blocks;
    size_t size, cap;
};

struct block* find_block(struct blockchain blockchain, uint32_t target_sha[8]);
struct blockchain create_chain(size_t num_blocks);
struct block* prev_block(struct blockchain chain, struct block* b);
void add_block(struct blockchain* chain, struct block* b);
inline struct block* root_block(struct blockchain* b);
void free_chain();
struct merkle* merkle_ledger(struct ledger* l, size_t start, size_t end);
int merkle_add(struct merkle* m, struct transaction t);
void merkle_block(struct block* b);

inline struct block* root_block(struct blockchain* b)
{
    if(b == NULL || b->blocks == NULL) return NULL;
    return &b->blocks[0];
}

struct contract
{
    uint8_t* code; // best if bytecode
    struct {
        uint32_t address[8]; // sha of the block
        void* other;
    } data;
};

struct transaction* get_contract_transaction(struct block* b);
void deploy_contract(struct blockchain b, struct contract* c);
void print_block(struct block* b);