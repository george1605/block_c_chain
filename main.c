#include "block.h"

int main()
{
    crypto_setup();

    struct block* b = init_block(2);
    uint32_t max_sha[8] = {0x0};
   
    bits_to_target(b->header.difficulty, (uint8_t*)max_sha);
    print_hash(max_sha, ' ');

    b->data.t[0] =  (struct transaction){.amount = 0.1f, .from = SYSTEM_ID, .to = 0x1ff000};
    b->data.t[1] =  (struct transaction){.amount = 0.05f, .from = SYSTEM_ID, .to = 0x1ea000};

    printf("Got this: %i", mine_block(b, max_sha));

    if(!validate_sha(b)) {
        printf("Got wrong sha!");
        print_block_hash(b);
        exit(0);
    }
    print_block_hash(b);
    printf("\nTries: %i", b->header.nonce);
    return 0;
}