#include <stdlib.h>
#include <runtime.h>
#include <stdbool.h>
#include <stdio.h>
#define EXIT_FAILURE 1
#define EXIT_SUCCESS 0

int main (int argc, char* argv[]) {
    bool passed = true;
    if (!passed) {
        printf("tests failed");
        msg_err("test failed");
        exit(EXIT_FAILURE);
    }
    
    printf("tests passed\n");
    exit(EXIT_SUCCESS);      
}