#ifndef _WORDLIST_H
#define _WORDLIST_H
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "MD5.h"

//Struct per modellare lettura della wordlist
typedef struct{
    int error_code;
    password *array_password;       //Array di password lette dalla wordlist
    unsigned int num_password;      //Numero di entry dell'array di password
}result_wordlist;

int count_lines(FILE *f1);
result_wordlist read_wordlist(char *fileName);
#endif