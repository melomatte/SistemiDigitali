#ifndef _MD5_VETTORIALE_H
#define _MD5_VETTORIALE_H
#include "utils.h"

uint64_t md5_vettoriale(password *array_password, unsigned int num_password, hash *array_hash);
uint64_t md5_vettoriale_v1(password *array_password, unsigned int num_password, hash *array_hash);
uint64_t md5_vettoriale_v2(password *array_password, unsigned int num_password, hash *array_hash);
uint64_t md5_vettoriale_v3(password *array_password, unsigned int num_password, hash *array_hash);
#endif