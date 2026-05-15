/*
* Executes the bytecode of a contract. Uses the EVM (Ethereum Virtual Machine) instruction set. This is a very basic implementation and does not include all the features of the EVM, but it should be enough to get started.
*/

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "block.h"

typedef uint8_t uint256_t[32]; // 256-bit unsigned integer

typedef struct {
    uint256_t stack[1024];   // or uint64_t[4] / uint8_t[32]
    int sp;                  // stack pointer

    uint8_t *memory;        
    size_t mem_size;

    uint8_t *code;          // bytecode being executed
    size_t code_size;

    size_t pc;              // program counter
    uint64_t gas;           // gas remaining

    uint256_t storage[1024]; // persistent key-value storage (simplified)
} EVM;

void stack_dump(EVM* evm) {
    printf("Stack (top to bottom):\n");
    for (int i = evm->sp - 1; i >= 0; i--) {
        printf("  [%d]: ", i);
        for (int j = 0; j < 32; j++) {
            printf("%02x", evm->stack[i][j]);
        }
        printf("\n");
    }
}

void execute_bytecode(EVM* evm)
{
    int result = 0, i = 0;
    assert(evm != NULL && "EVM context must not be NULL");

    uint8_t* code = (uint8_t*)evm->code;
    while(evm->pc < evm->code_size)
    {
        switch(code[i])
        {
        case 0x00: // STOP
            goto end_func;
        case 0x60: // PUSH1
            evm->stack[evm->sp / 32][evm->sp % 32] = code[++i]; // Push next byte onto stack
            evm->sp += 1;
            break;
        case 0x50: // POP 
            evm->sp -= 1;
            break;
        case 0x80: // DUP1
            memcpy(evm->stack[(evm->sp) / 32], evm->stack[(evm->sp - 1) / 32], 1); // Duplicate top of stack
            evm->sp += 1;
            break;
        case 0x54:
            evm->sp -= 1; // SLOAD
            memcpy(evm->stack[evm->sp / 32], evm->storage[0], 32);
            break;
        case 0x01:
            result = evm->stack[(evm->sp - 1) / 32][(evm->sp - 1) % 32] + evm->stack[(evm->sp - 2) / 32][(evm->sp - 2) % 32]; 
            evm->stack[(evm->sp - 2) / 32][(evm->sp - 2) % 32] = result; 
            evm->sp -= 1; // Pop two values
            break;
        }
        i++;
        evm->pc++;
    }

end_func:
    stack_dump(evm);
}

// Execute the transactions in a block (contracts)
void execute_trans_block(struct block* b)
{
    for(int i = 0; i < b->data.size; i++) {
        if(b->data.t[i].to == NULL) 
        {
            EVM evm;
            memset(&evm, 0, sizeof(EVM));
            evm.code = (uint8_t*)b->data.t[i].data;
            evm.code_size = b->data.t[i].amount;
            execute_bytecode(&evm);
        }
    }
}

int main()
{
    struct block b;
    uint8_t bytecode[] = {0x60, 0x02, 0x60, 0x07, 0x01};

    b.data.t = (struct transaction*)malloc(sizeof(struct transaction) * 1);
    b.data.size = 1;

    b.data.t[0].to = NULL; // Indicating this is a contract deployment
    b.data.t[0].data = bytecode;
    b.data.t[0].amount = sizeof(bytecode); 

    execute_trans_block(&b);

    free(b.data.t);
    return 0;
}