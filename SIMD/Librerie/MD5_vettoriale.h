#ifndef _MD5_VETTORIALE_H
#define _MD5_VETTORIALE_H
#include "utils.h"

uint64_t md5_vettoriale(password *array_password, unsigned int num_password, uint8_t *hash_tocrack, int modalita_test);
uint64_t md5_vettoriale_v1(password *array_password, unsigned int num_password, uint8_t *hash_tocrack, int modalita_test);
uint64_t md5_vettoriale_v2(password *array_password, unsigned int num_password, uint8_t *hash_tocrack, int modalita_test);
uint64_t md5_vettoriale_v3(password *array_password, unsigned int num_password, uint8_t *hash_tocrack, int modalita_test);
#endif
