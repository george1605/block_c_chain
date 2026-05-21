#include "serialize.h"

int main()
{
    struct block* b;
    crypto_setup();
    b = init_block(2); // can hold 2 transactions
    add_transaction_to_block(b, init_transaction(1, 2, 100));
    add_transaction_to_block(b, init_transaction(2, 1, 50));
    print_block(b);

    struct serializer* s = serializer_create(100);
    FILE* f = fopen("block.dat", "wb");

    if(f == NULL) {
        serializer_write_packet(s, b);
        serializer_send_file(s, "block.dat");
        serializer_close(s);
    } else {
        fclose(f);
        serializer_read_file(s, "block.dat");
        struct block* b2 = init_block(2);
        serializer_read_packet(s, b2);
        print_block_hash(b2);
        printf("Number of transactions: %zu\n", b2->data.size);
        free_block(b2);
    }

    free_block(b);
}