#include "MD5.h"

__m128i K_register[64];
__m128i a0_init;
__m128i b0_init;
__m128i c0_init;
__m128i d0_init;


void deallocation(uint8_t **padded_password, unsigned int num_password) {
    for (unsigned int i = 0; i < num_password; i++) {
            _mm_free(padded_password[i]);
    }
    _mm_free(padded_password);
}

uint8_t** padding_vettoriale(password *array_password, unsigned int *num_password){
    unsigned int i;
    uint8_t diff, j, k;

    //Padding richiesto da MD5_vettoriale-Le password non sono multiple di 4
    if (*num_password % 4 != 0) {
        diff = 4 - (*num_password % 4);
        *num_password += diff;
    }

    uint8_t **padded_password = (uint8_t **) _mm_malloc(*num_password * sizeof(uint8_t *), 16);
    for(i = 0; i < (*num_password); i++){
        padded_password[i] = (uint8_t *) _mm_malloc(64, 16);
    }

    for(i = 0; i < (*num_password) - diff; i++){
        memcpy(padded_password[i], array_password[i].pwd, array_password[i].len_pwd);
        padded_password[i][array_password[i].len_pwd] = 0x80; // padded_password[0..len_password-1] = password; padded_password[len_password] = 1000 0000
        for (j = array_password[i].len_pwd + 1; j < 56; j++) {    //padded_password[len_password+1..56] = 0000 0000
            padded_password[i][j] = 0x00;
        }
        uint64_t len_password_bits = array_password[i].len_pwd * 8; // len_password in bit
        memcpy(padded_password[i] + 56, &len_password_bits, 8); // padded_password[56..63] = len_password_bits
    }

    //Le password aggiuntive per far diventare il numero multiplo di 4 vengono poste a 0
    for (k = 0; k < diff; k++) {
        for (j = 0; j < 64; j++) {
            padded_password[(*num_password) - diff + k][j] = 0x00;
        }
    }

    return padded_password;
}

void initialization(){
    unsigned int i;
    uint8_t j, k;
    uint32_t combo;

    //register void initialization
    for(int i = 0; i < 64; i++) K_register[i] = _mm_set1_epi32 (K[i]);

    a0_init = _mm_set1_epi32 (0x67452301);
    b0_init = _mm_set1_epi32 (0xefcdab89);
    c0_init = _mm_set1_epi32 (0x98badcfe);
    d0_init = _mm_set1_epi32 (0x10325476);
    /*
    //Disposizione efficiente dei dati in memoria per eseguire _mm_load
    uint32_t **M = (uint32_t **) _mm_malloc(num_password/4 * sizeof(uint32_t *), 16);
    for(i = 0; i < num_password/4; i++){
        M[i] = (uint32_t *) _mm_malloc(64*4*sizeof(uint32_t), 16);
    }

    for(i = 0; i < num_password/4; i++){
        for(j = 0; j < 64; j++){
            for(k = 0; k < 4; k++){
                combo = (uint32_t)(padded_password[i * 4 + k][g[j] * 4]) |
                        (uint32_t)(padded_password[i * 4 + k][g[j] * 4 + 1]) << 8 |
                        (uint32_t)(padded_password[i * 4 + k][g[j] * 4 + 2]) << 16 |
                        (uint32_t)(padded_password[i * 4 + k][g[j] * 4 + 3]) << 24;
                M[i][j*4+k] = combo;
            }
        }
    }*/
}

uint8_t** padding_scalare(password *array_password, unsigned int num_password){
    uint8_t **padded_password = (uint8_t **) _mm_malloc(num_password * sizeof(uint8_t *), 16);
    unsigned int i;
    uint8_t j;

    for(i = 0; i < num_password; i++){
        padded_password[i] = (uint8_t *) _mm_malloc(64, 16);
    }

    for(i = 0; i < num_password; i++){
        memcpy(padded_password[i], array_password[i].pwd, array_password[i].len_pwd);
        padded_password[i][array_password[i].len_pwd] = 0x80; // padded_password[0..len_password-1] = password; padded_password[len_password] = 1000 0000
        for (j = array_password[i].len_pwd + 1; j < 56; j++) {    //padded_password[len_password+1..56] = 0000 0000
            padded_password[i][j] = 0x00;
        }
        uint64_t len_password_bits = array_password[i].len_pwd * 8; // len_password in bit
        memcpy(padded_password[i] + 56, &len_password_bits, 8); // padded_password[56..63] = len_password_bits
    }

    return padded_password;
}

uint64_t md5(password *array_password, unsigned int num_password, hash *array_hash) {
    // Padding password
    // Assunzione di base -> tutte le password presentano una lunghezza minore di 64 caratteri (64 byte), ovvero sono costituite da un solo chunk
    uint32_t a0, A;
    uint32_t b0, B;
    uint32_t c0, C;
    uint32_t d0, D;
    uint32_t F;


    uint64_t inizio_elaborazione = __rdtsc();
    uint8_t **padded_password = padding_scalare(array_password, num_password);

    //Per ogni parola, viene preso in considerazione l'unico chunk da 64 byte
    for(unsigned int k = 0; k < num_password; k++){
        // Variabili iniziali MD5 (32 bit unsigned)
        a0 = 0x67452301;
        b0 = 0xefcdab89;
        c0 = 0x98badcfe;
        d0 = 0x10325476;

        // Il chunk viene diviso in elementi da 32 bit (64 byte -> 16 elementi da 32 bit)
        uint32_t *M = (uint32_t *)(padded_password[k]);

        // A, B, C, D assumono i valori iniziali delle variabili a0, b0, c0, d0
        A = a0, B = b0, C = c0, D = d0;

        // 4 round di 16 operazioni
        for (uint16_t i = 0; i < 64; i++) {
            //~ -> operatore bitwise NOT, inverte i bit (gli 0 diventano 1 e viceversa)
            //^ -> operatore XOR
            if (i <= 15) {
                F = (B & C) | (~B & D);
            } else if (i >= 16 && i <= 31) {
                F = (D & B) | (~D & C);
            } else if (i >= 32 && i <= 47) {
                F = B ^ C ^ D;
            } else {
                F = C ^ (B | ~D);
            }
                        
            F = A + F + K[i] + M[g[i]];
            A = D;
            D = C;
            C = B;
            B = B + LEFTROTATE(F, s[i]);
        }
        
        // Fine elaborazione chunk -> aggiorno variabili
        a0 += A;
        b0 += B;
        c0 += C;
        d0 += D;

        // hash -> insieme delle 4 variabili a 32 bit
        memcpy(array_hash[k].hash, &a0, 4);
        memcpy(array_hash[k].hash + 4, &b0, 4);
        memcpy(array_hash[k].hash + 8, &c0, 4);
        memcpy(array_hash[k].hash + 12, &d0, 4);
    }
    uint64_t fine_elaborazione = __rdtsc();

    deallocation(padded_password, num_password);

    return (fine_elaborazione - inizio_elaborazione);
}

uint64_t md5_vettoriale(password *array_password, unsigned int num_password, hash *array_hash){
    initialization();

    uint8_t i = 0;
    uint32_t *M_0, *M_1, *M_2, *M_3;
    __m128i *p_K;
    //__m128i *p_M;
    __m128i F;
    __m128i M_register;
    __m128i a0, A;
    __m128i b0, B;
    __m128i c0, C;
    __m128i d0, D;
    __m128i lo_a0_b0;
    __m128i hi_a0_b0;
    __m128i lo_c0_d0;
    __m128i hi_c0_d0;
    __m128i first_hash;
    __m128i second_hash;
    __m128i third_hash;
    __m128i fourth_hash;

    uint64_t inizio_elaborazione = __rdtsc();
    uint8_t **padded_password = padding_vettoriale(array_password, &num_password);

    //Le password vengono processate al passo di 4
    for(unsigned int k = 0; k < num_password/4; k++){
        p_K = (__m128i *)array_hash[k*4].hash;
        // Registri iniziali -> ogni registro contiene 4 elementi da 32 bit, tutti che assumono il valore di inizializzazione
        a0 = a0_init;
        b0 = b0_init;
        c0 = c0_init;
        d0 = d0_init;

        // I registeri A, B, C, D sono i registeri in cui avviene il calcolo -> assumono i valori iniziali dei registeri a0, b0, c0, d0
        A = a0, B = b0, C = c0, D = d0;

        // 4 round di 16 operazioni
        //p_M = (_m128i *)M[k];
        M_0 = (uint32_t *)padded_password[k*4];
        M_1 = (uint32_t *)padded_password[k*4+1];
        M_2 = (uint32_t *)padded_password[k*4+2];
        M_3 = (uint32_t *)padded_password[k*4+3];

        // 4 round di 16 operazioni
        for (uint8_t i = 0; i < 64; i++) {
            if (i <= 15) {
                F = _mm_or_si128 (_mm_and_si128 (B, C), _mm_andnot_si128 (B, D));
            } else if (i >= 16 && i <= 31) {
                F = _mm_or_si128 (_mm_and_si128 (D, B), _mm_andnot_si128 (D, C));
            } else if (i >= 32 && i <= 47) {
                F = _mm_xor_si128 (_mm_xor_si128(B, C), D);
            } else {
                //Il NOT di un registro è stato ottenuto come XOR tra il registro e maschera di 1 (si utilizza -1 in quanto la codifica in binario è pari a 1111 1111)
                F = _mm_xor_si128 (C, _mm_or_si128 (B, _mm_xor_si128 (D, _mm_set1_epi8(-1))));
            }

            M_register = _mm_set_epi32(M_3[g[i]], M_2[g[i]] , M_1[g[i]], M_0[g[i]]);
            
            F = _mm_add_epi32(_mm_add_epi32(A, F), _mm_add_epi32(K_register[i], M_register));            
            A = D;
            D = C;
            C = B;
            B = _mm_add_epi32(B, _mm_or_si128 (_mm_slli_epi32 (F, s[i]), _mm_srli_epi32 (F, 32-s[i])));
        }

        // Fine elaborazione chunk -> aggiorno variabili
        a0 = _mm_add_epi32(a0, A);
        b0 = _mm_add_epi32(b0, B);
        c0 = _mm_add_epi32(c0, C);
        d0 = _mm_add_epi32(d0, D);

        // 4 hash calcolati ma i valori dell'hash sono su 4 registri differenti
        lo_a0_b0 = _mm_unpacklo_epi32(a0, b0);
        hi_a0_b0 = _mm_unpackhi_epi32(a0, b0);
        lo_c0_d0 = _mm_unpacklo_epi32(c0, d0);
        hi_c0_d0 = _mm_unpackhi_epi32(c0, d0);

        first_hash = _mm_unpacklo_epi32(lo_a0_b0, lo_c0_d0);
        second_hash = _mm_unpackhi_epi32(lo_a0_b0,lo_c0_d0);
        third_hash = _mm_unpacklo_epi32(hi_a0_b0, hi_c0_d0);
        fourth_hash = _mm_unpackhi_epi32(hi_a0_b0, hi_c0_d0);
        
        _mm_store_si128(p_K, _mm_shuffle_epi32(first_hash, 216));
        _mm_store_si128(p_K + 1, _mm_shuffle_epi32(second_hash, 216));
        _mm_store_si128(p_K + 2, _mm_shuffle_epi32(third_hash, 216));
        _mm_store_si128(p_K + 3, _mm_shuffle_epi32(fourth_hash, 216));
        
    }

    uint64_t fine_elaborazione = __rdtsc();
    
    deallocation(padded_password, num_password);

    return (fine_elaborazione - inizio_elaborazione);
}
