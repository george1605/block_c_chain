/*
* Executes the bytecode or executes the programmer (jk)
*/

#include <stdio.h>
#include <string.h>
#include "block.c"

void execute_bytecode(char* code, struct blockchain chain)
{
    for(int i = 0;code[i] != '\0';i++)
    {
        switch(code[i])
        {
        case 0x01:

        }
    }
}