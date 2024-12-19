#ifndef _WORDLIST_H
#define _WORDLIST_H
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

//Struct per modellare attributi singola password contenute nella wordlist
typedef struct{
    char pwd[56];
    uint8_t len_pwd;
}password;

//Struct per modellare lettura della wordlist
typedef struct{
    int error_code;
    password *array_password;       //Array di password lette dalla wordlist
    unsigned int num_password;      //Numero di entry dell'array di password
}result_wordlist;

//Struct per modellare attributi singolo hash di una password
typedef struct{
    char hash[16];
}hash;

int count_lines(FILE *f1);
result_wordlist read_wordlist(char *fileName);
#endif