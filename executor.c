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

void execute_bytecode(EVM* evm)
{
    int result = 0, i = 0;
    assert(evm != NULL && "EVM context must not be NULL");

    uint8_t* code = (uint8_t*)evm->code;
    while(evm->pc < evm->code_size)
    {
        switch(code[i])
        {
        case 0x60: // PUSH1
            evm->stack[evm->sp / 32][evm->sp % 32] = code[++i]; // Push next byte onto stack
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
}

int main()
{
    EVM evm;
    memset(&evm, 0, sizeof(EVM));

    // Example bytecode: PUSH1 0x2 PUSH1 0x3 ADD
    uint8_t bytecode[] = {0x60, 0x02, 0x60, 0x03, 0x01};
    evm.code = bytecode;
    evm.code_size = sizeof(bytecode);

    execute_bytecode(&evm);
    printf("Result on stack: %d\n", evm.stack[(evm.sp - 1) / 32][(evm.sp - 1) % 32]); // Should print 5
    return 0;
}