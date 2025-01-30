#include "utils.h"

//Funzioni ausiliarie di deallocazione di memoria dinamica
void deallocation8(uint8_t **padded_password, unsigned int num_password) {
    for (unsigned int i = 0; i < num_password; i++) {
            _mm_free(padded_password[i]);
    }
    _mm_free(padded_password);
}

void deallocation32(uint32_t **padded_password, unsigned int num_password) {
    for (unsigned int i = 0; i < num_password; i++) {
            _mm_free(padded_password[i]);
    }
    _mm_free(padded_password);
}

//Funzione per convertire ogni carattere nel suo valore esadecimale
uint8_t hex_char_to_value(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    } else {
        return c - 'a' + 10;
    }
}

//Funzione per controllare la correttezza dell'hash inserito in input
bool hash_valid(char* stringa_hash) {
    bool sentinella = true;
    int i;
    for (i = 0; stringa_hash[i] != '\0'; i++) {
        if (i > 31 || !(isdigit(stringa_hash[i]) || (stringa_hash[i] >= 'a' && stringa_hash[i] <= 'z'))) {
            sentinella = false;
        }
    }
    if (i != 32) sentinella = false;
    return sentinella;
}

//Funzione ausiliaria utilizzata per debug
void print_hash(uint8_t *hash) {
    for (uint8_t i = 0; i < 16; i++) {
        printf("%02x", (unsigned char) hash[i]);  // Stampa ogni byte in formato esadecimale
    }
    printf("\n");
}
