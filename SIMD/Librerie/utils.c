#include "utils.h"

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