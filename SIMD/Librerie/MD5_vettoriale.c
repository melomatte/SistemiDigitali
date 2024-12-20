#include "MD5_vettoriale.h"

__m128i K_register[64];
__m128i a0_init;
__m128i b0_init;
__m128i c0_init;
__m128i d0_init;

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

/********
 VERSIONE PIÙ EFFICIENTE
********/

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
}

uint64_t md5_vettoriale(password *array_password, unsigned int num_password, hash *array_hash){
    uint8_t **padded_password = padding_vettoriale(array_password, &num_password);
    initialization();

    uint8_t i = 0;
    uint32_t *M_0, *M_1, *M_2, *M_3;
    __m128i *p_K;
    __m128i F;
    __m128i M_register;
    __m128i a0, A;
    __m128i b0, B;
    __m128i c0, C;
    __m128i d0, D;
    __m128i first_and, first_andnot;
    __m128i second_and, second_andnot;
    __m128i third_xor;
    __m128i fourth_xor, fourth_or;
    __m128i lo_a0_b0;
    __m128i hi_a0_b0;
    __m128i lo_c0_d0;
    __m128i hi_c0_d0;
    __m128i first_hash, first_hash_uns;
    __m128i second_hash, second_hash_uns;
    __m128i third_hash, third_hash_uns;
    __m128i fourth_hash, fourth_hash_uns;
    __m128i registro_1 = _mm_set1_epi8(-1); //maschera di 1 (si utilizza -1 in quanto la codifica in binario è pari a 1111 1111)

    uint64_t inizio_elaborazione = __rdtsc();

    //Le password vengono processate al passo di 4
    for(unsigned int k = 0; k < num_password/4; k++){
        p_K = (__m128i *)array_hash[k*4].hash;

        // I registeri A, B, C, D sono i registeri in cui avviene il calcolo -> assumono i valori iniziali dei registeri a0, b0, c0, d0
        A = a0_init;
        B = b0_init;
        C = c0_init;
        D = d0_init;

        // 4 round di 16 operazioni
        M_0 = (uint32_t *)padded_password[k*4];
        M_1 = (uint32_t *)padded_password[k*4+1];
        M_2 = (uint32_t *)padded_password[k*4+2];
        M_3 = (uint32_t *)padded_password[k*4+3];


        // 4 round di 16 operazioni
        for(i = 0; i < 16; i++){
            first_and = _mm_and_si128 (B, C);
            first_andnot = _mm_andnot_si128 (B, D);
            F = _mm_or_si128 (first_and, first_andnot);

            M_register = _mm_set_epi32(M_3[g[i]], M_2[g[i]], M_1[g[i]], M_0[g[i]]);
            
            F = _mm_add_epi32(_mm_add_epi32(A, F), _mm_add_epi32(K_register[i], M_register));            
            A = D;
            D = C;
            C = B;
            B = _mm_add_epi32(B, _mm_or_si128 (_mm_slli_epi32 (F, s[i]), _mm_srli_epi32 (F, 32-s[i])));
        }

        for(i = 16; i < 32; i++){
            second_and = _mm_and_si128 (D, B);
            second_andnot = _mm_andnot_si128 (D, C);
            F = _mm_or_si128 (second_and, second_andnot);

            M_register = _mm_set_epi32(M_3[g[i]], M_2[g[i]], M_1[g[i]], M_0[g[i]]);
            
            F = _mm_add_epi32(_mm_add_epi32(A, F), _mm_add_epi32(K_register[i], M_register));            
            A = D;
            D = C;
            C = B;
            B = _mm_add_epi32(B, _mm_or_si128 (_mm_slli_epi32 (F, s[i]), _mm_srli_epi32 (F, 32-s[i])));
        }

        for(i = 32; i < 48; i++){
            third_xor = _mm_xor_si128(B, C);
            F = _mm_xor_si128 (third_xor, D);

            M_register = _mm_set_epi32(M_3[g[i]], M_2[g[i]], M_1[g[i]], M_0[g[i]]);
            
            F = _mm_add_epi32(_mm_add_epi32(A, F), _mm_add_epi32(K_register[i], M_register));            
            A = D;
            D = C;
            C = B;
            B = _mm_add_epi32(B, _mm_or_si128 (_mm_slli_epi32 (F, s[i]), _mm_srli_epi32 (F, 32-s[i])));
        }

        for(i = 48; i < 64; i++){
            fourth_xor = _mm_xor_si128 (D, registro_1);
            fourth_or = _mm_or_si128 (B, fourth_xor);
            F = _mm_xor_si128 (C, fourth_or);

            M_register = _mm_set_epi32(M_3[g[i]], M_2[g[i]], M_1[g[i]], M_0[g[i]]);
            
            F = _mm_add_epi32(_mm_add_epi32(A, F), _mm_add_epi32(K_register[i], M_register));            
            A = D;
            D = C;
            C = B;
            B = _mm_add_epi32(B, _mm_or_si128 (_mm_slli_epi32 (F, s[i]), _mm_srli_epi32 (F, 32-s[i])));
        }

        // Fine elaborazione chunk -> aggiorno variabili
        A = _mm_add_epi32(a0_init, A);
        B = _mm_add_epi32(b0_init, B);
        C = _mm_add_epi32(c0_init, C);
        D = _mm_add_epi32(d0_init, D);

        // 4 hash calcolati ma i valori dell'hash sono su 4 registri differenti
        lo_a0_b0 = _mm_unpacklo_epi32(A, B);
        hi_a0_b0 = _mm_unpackhi_epi32(A, B);
        lo_c0_d0 = _mm_unpacklo_epi32(C, D);
        hi_c0_d0 = _mm_unpackhi_epi32(C, D);

        first_hash_uns = _mm_unpacklo_epi32(lo_a0_b0, lo_c0_d0);
        second_hash_uns = _mm_unpackhi_epi32(lo_a0_b0,lo_c0_d0);
        third_hash_uns = _mm_unpacklo_epi32(hi_a0_b0, hi_c0_d0);
        fourth_hash_uns = _mm_unpackhi_epi32(hi_a0_b0, hi_c0_d0);

        first_hash = _mm_shuffle_epi32(first_hash_uns, 216);
        second_hash = _mm_shuffle_epi32(second_hash_uns, 216);
        third_hash = _mm_shuffle_epi32(third_hash_uns, 216);
        fourth_hash = _mm_shuffle_epi32(fourth_hash_uns, 216);
        
        _mm_store_si128(p_K, first_hash);
        _mm_store_si128(p_K + 1, second_hash);
        _mm_store_si128(p_K + 2, third_hash);
        _mm_store_si128(p_K + 3, fourth_hash);
        
    }

    uint64_t fine_elaborazione = __rdtsc();
    
    deallocation8(padded_password, num_password);

    return (fine_elaborazione - inizio_elaborazione);
}

/********
 VERSIONE CON DISPOSIZIONE EFFICIENTE DEI DATI IN MEMORIA (SALVATI ALL'INTERNO DI REGISTRI ESTESI) -> POSSIBILE OVERHEAD DEI REGISTRI
********/

__m128i** initialization_v1(uint8_t** padded_password, unsigned int num_password){
    unsigned int i;
    uint8_t j, k;
    uint32_t combo;

    //register void initialization
    for(int i = 0; i < 64; i++) K_register[i] = _mm_set1_epi32 (K[i]);

    a0_init = _mm_set1_epi32 (0x67452301);
    b0_init = _mm_set1_epi32 (0xefcdab89);
    c0_init = _mm_set1_epi32 (0x98badcfe);
    d0_init = _mm_set1_epi32 (0x10325476);

    //Disposizione efficiente dei dati in memoria per eseguire _mm_load
    uint32_t **M = (uint32_t **) _mm_malloc(num_password/4 * sizeof(uint32_t *), 16);
    for(i = 0; i < num_password/4; i++){
        M[i] = (uint32_t *) _mm_malloc(64*4*sizeof(uint32_t), 16);
    }

    __m128i **M_register = (__m128i **) _mm_malloc(num_password/4 * sizeof(__m128i *), 16);
    for(i = 0; i < num_password/4; i++){
        M_register[i] = (__m128i *) _mm_malloc(64*4*sizeof(__m128i), 16);
    }

    __m128i* p_M;

    for(i = 0; i < num_password/4; i++){
        p_M = (__m128i *) M[i];
        for(j = 0; j < 64; j++){
            for(k = 0; k < 4; k++){
                combo = (uint32_t)(padded_password[i * 4 + k][g[j] * 4]) |
                        (uint32_t)(padded_password[i * 4 + k][g[j] * 4 + 1]) << 8 |
                        (uint32_t)(padded_password[i * 4 + k][g[j] * 4 + 2]) << 16 |
                        (uint32_t)(padded_password[i * 4 + k][g[j] * 4 + 3]) << 24;
                M[i][j*4+k] = combo;
            }
            M_register[i][j] = _mm_load_si128(p_M+j);
        }
    }

    deallocation32(M,num_password/4);

    return M_register;
}

uint64_t md5_vettoriale_v1(password *array_password, unsigned int num_password, hash *array_hash){
    uint8_t **padded_password = padding_vettoriale(array_password, &num_password);
    __m128i** M_register;
    M_register = initialization_v1(padded_password, num_password);

    uint8_t i = 0;
    __m128i *p_K;
    __m128i F;
    __m128i a0, A;
    __m128i b0, B;
    __m128i c0, C;
    __m128i d0, D;
    __m128i first_and, first_andnot;
    __m128i second_and, second_andnot;
    __m128i third_xor;
    __m128i fourth_xor, fourth_or;
    __m128i lo_a0_b0;
    __m128i hi_a0_b0;
    __m128i lo_c0_d0;
    __m128i hi_c0_d0;
    __m128i first_hash, first_hash_uns;
    __m128i second_hash, second_hash_uns;
    __m128i third_hash, third_hash_uns;
    __m128i fourth_hash, fourth_hash_uns;
    __m128i registro_1 = _mm_set1_epi8(-1); //maschera di 1 (si utilizza -1 in quanto la codifica in binario è pari a 1111 1111)

    uint64_t inizio_elaborazione = __rdtsc();

    //Le password vengono processate al passo di 4
    for(unsigned int k = 0; k < num_password/4; k++){
        p_K = (__m128i *)array_hash[k*4].hash;

        // I registeri A, B, C, D sono i registeri in cui avviene il calcolo -> assumono i valori iniziali dei registeri a0, b0, c0, d0
        A = a0_init;
        B = b0_init;
        C = c0_init;
        D = d0_init;

        // 4 round di 16 operazioni
        for (uint8_t i = 0; i < 64; i++) {
            if (i <= 15) {
                first_and = _mm_and_si128 (B, C);
                first_andnot = _mm_andnot_si128 (B, D);
                F = _mm_or_si128 (first_and, first_andnot);
            } else if (i >= 16 && i <= 31) {
                second_and = _mm_and_si128 (D, B);
                second_andnot = _mm_andnot_si128 (D, C);
                F = _mm_or_si128 (second_and, second_andnot);
            } else if (i >= 32 && i <= 47) {
                third_xor = _mm_xor_si128(B, C);
                F = _mm_xor_si128 (third_xor, D);
            } else {
                fourth_xor = _mm_xor_si128 (D, registro_1);
                fourth_or = _mm_or_si128 (B, fourth_xor);
                F = _mm_xor_si128 (C, fourth_or);
            }
            
            F = _mm_add_epi32(_mm_add_epi32(A, F), _mm_add_epi32(K_register[i], M_register[k][i]));            
            A = D;
            D = C;
            C = B;
            B = _mm_add_epi32(B, _mm_or_si128 (_mm_slli_epi32 (F, s[i]), _mm_srli_epi32 (F, 32-s[i])));
        }

        // Fine elaborazione chunk -> aggiorno variabili
        A = _mm_add_epi32(a0_init, A);
        B = _mm_add_epi32(b0_init, B);
        C = _mm_add_epi32(c0_init, C);
        D = _mm_add_epi32(d0_init, D);

        // 4 hash calcolati ma i valori dell'hash sono su 4 registri differenti
        lo_a0_b0 = _mm_unpacklo_epi32(A, B);
        hi_a0_b0 = _mm_unpackhi_epi32(A, B);
        lo_c0_d0 = _mm_unpacklo_epi32(C, D);
        hi_c0_d0 = _mm_unpackhi_epi32(C, D);

        first_hash_uns = _mm_unpacklo_epi32(lo_a0_b0, lo_c0_d0);
        second_hash_uns = _mm_unpackhi_epi32(lo_a0_b0,lo_c0_d0);
        third_hash_uns = _mm_unpacklo_epi32(hi_a0_b0, hi_c0_d0);
        fourth_hash_uns = _mm_unpackhi_epi32(hi_a0_b0, hi_c0_d0);

        first_hash = _mm_shuffle_epi32(first_hash_uns, 216);
        second_hash = _mm_shuffle_epi32(second_hash_uns, 216);
        third_hash = _mm_shuffle_epi32(third_hash_uns, 216);
        fourth_hash = _mm_shuffle_epi32(fourth_hash_uns, 216);
        
        _mm_store_si128(p_K, first_hash);
        _mm_store_si128(p_K + 1, second_hash);
        _mm_store_si128(p_K + 2, third_hash);
        _mm_store_si128(p_K + 3, fourth_hash);
        
    }

    uint64_t fine_elaborazione = __rdtsc();
    
    deallocation8(padded_password, num_password);

    for (unsigned int i = 0; i < num_password/4; i++) {
            _mm_free(M_register[i]);
    }
    _mm_free(M_register);

    return (fine_elaborazione - inizio_elaborazione);
}

/********
 VERSIONE CON DISPOSIZIONE EFFICIENTE DEI DATI IN MEMORIA -> OPERAZIONE DI SET
********/

uint32_t** initialization_v2_v3(uint8_t** padded_password, unsigned int num_password){
    unsigned int i;
    uint8_t j, k;
    uint32_t combo;

    //register void initialization
    for(int i = 0; i < 64; i++) K_register[i] = _mm_set1_epi32 (K[i]);

    a0_init = _mm_set1_epi32 (0x67452301);
    b0_init = _mm_set1_epi32 (0xefcdab89);
    c0_init = _mm_set1_epi32 (0x98badcfe);
    d0_init = _mm_set1_epi32 (0x10325476);

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
    }

    return M;
 
}

uint64_t md5_vettoriale_v2(password *array_password, unsigned int num_password, hash *array_hash){
    uint8_t **padded_password = padding_vettoriale(array_password, &num_password);
    uint32_t **M = initialization_v2_v3(padded_password, num_password);

    uint8_t i = 0;
    __m128i *p_K;
    __m128i F;
    __m128i M_register;
    __m128i a0, A;
    __m128i b0, B;
    __m128i c0, C;
    __m128i d0, D;
    __m128i first_and, first_andnot;
    __m128i second_and, second_andnot;
    __m128i third_xor;
    __m128i fourth_xor, fourth_or;
    __m128i lo_a0_b0;
    __m128i hi_a0_b0;
    __m128i lo_c0_d0;
    __m128i hi_c0_d0;
    __m128i first_hash, first_hash_uns;
    __m128i second_hash, second_hash_uns;
    __m128i third_hash, third_hash_uns;
    __m128i fourth_hash, fourth_hash_uns;
    __m128i registro_1 = _mm_set1_epi8(-1); //maschera di 1 (si utilizza -1 in quanto la codifica in binario è pari a 1111 1111)

    uint64_t inizio_elaborazione = __rdtsc();

    //Le password vengono processate al passo di 4
    for(unsigned int k = 0; k < num_password/4; k++){
        p_K = (__m128i *)array_hash[k*4].hash;

        // I registeri A, B, C, D sono i registeri in cui avviene il calcolo -> assumono i valori iniziali dei registeri a0, b0, c0, d0
        A = a0_init;
        B = b0_init;
        C = c0_init;
        D = d0_init;


        // 4 round di 16 operazioni
        for(i = 0; i < 16; i++){
            first_and = _mm_and_si128 (B, C);
            first_andnot = _mm_andnot_si128 (B, D);
            F = _mm_or_si128 (first_and, first_andnot);

            M_register = _mm_set_epi32(M[k][4*i+3], M[k][4*i+2], M[k][4*i+1], M[k][4*i]);
            
            F = _mm_add_epi32(_mm_add_epi32(A, F), _mm_add_epi32(K_register[i], M_register));            
            A = D;
            D = C;
            C = B;
            B = _mm_add_epi32(B, _mm_or_si128 (_mm_slli_epi32 (F, s[i]), _mm_srli_epi32 (F, 32-s[i])));
        }

        for(i = 16; i < 32; i++){
            second_and = _mm_and_si128 (D, B);
            second_andnot = _mm_andnot_si128 (D, C);
            F = _mm_or_si128 (second_and, second_andnot);

            M_register = _mm_set_epi32(M[k][4*i+3], M[k][4*i+2], M[k][4*i+1], M[k][4*i]);
            
            F = _mm_add_epi32(_mm_add_epi32(A, F), _mm_add_epi32(K_register[i], M_register));            
            A = D;
            D = C;
            C = B;
            B = _mm_add_epi32(B, _mm_or_si128 (_mm_slli_epi32 (F, s[i]), _mm_srli_epi32 (F, 32-s[i])));
        }

        for(i = 32; i < 48; i++){
            third_xor = _mm_xor_si128(B, C);
            F = _mm_xor_si128 (third_xor, D);

            M_register = _mm_set_epi32(M[k][4*i+3], M[k][4*i+2], M[k][4*i+1], M[k][4*i]);
            
            F = _mm_add_epi32(_mm_add_epi32(A, F), _mm_add_epi32(K_register[i], M_register));            
            A = D;
            D = C;
            C = B;
            B = _mm_add_epi32(B, _mm_or_si128 (_mm_slli_epi32 (F, s[i]), _mm_srli_epi32 (F, 32-s[i])));
        }

        for(i = 48; i < 64; i++){
            fourth_xor = _mm_xor_si128 (D, registro_1);
            fourth_or = _mm_or_si128 (B, fourth_xor);
            F = _mm_xor_si128 (C, fourth_or);

            M_register = _mm_set_epi32(M[k][4*i+3], M[k][4*i+2], M[k][4*i+1], M[k][4*i]);
            
            F = _mm_add_epi32(_mm_add_epi32(A, F), _mm_add_epi32(K_register[i], M_register));            
            A = D;
            D = C;
            C = B;
            B = _mm_add_epi32(B, _mm_or_si128 (_mm_slli_epi32 (F, s[i]), _mm_srli_epi32 (F, 32-s[i])));
        }

        // Fine elaborazione chunk -> aggiorno variabili
        A = _mm_add_epi32(a0_init, A);
        B = _mm_add_epi32(b0_init, B);
        C = _mm_add_epi32(c0_init, C);
        D = _mm_add_epi32(d0_init, D);

        // 4 hash calcolati ma i valori dell'hash sono su 4 registri differenti
        lo_a0_b0 = _mm_unpacklo_epi32(A, B);
        hi_a0_b0 = _mm_unpackhi_epi32(A, B);
        lo_c0_d0 = _mm_unpacklo_epi32(C, D);
        hi_c0_d0 = _mm_unpackhi_epi32(C, D);

        first_hash_uns = _mm_unpacklo_epi32(lo_a0_b0, lo_c0_d0);
        second_hash_uns = _mm_unpackhi_epi32(lo_a0_b0,lo_c0_d0);
        third_hash_uns = _mm_unpacklo_epi32(hi_a0_b0, hi_c0_d0);
        fourth_hash_uns = _mm_unpackhi_epi32(hi_a0_b0, hi_c0_d0);

        first_hash = _mm_shuffle_epi32(first_hash_uns, 216);
        second_hash = _mm_shuffle_epi32(second_hash_uns, 216);
        third_hash = _mm_shuffle_epi32(third_hash_uns, 216);
        fourth_hash = _mm_shuffle_epi32(fourth_hash_uns, 216);
        
        _mm_store_si128(p_K, first_hash);
        _mm_store_si128(p_K + 1, second_hash);
        _mm_store_si128(p_K + 2, third_hash);
        _mm_store_si128(p_K + 3, fourth_hash);
        
    }

    uint64_t fine_elaborazione = __rdtsc();
    
    deallocation8(padded_password, num_password);
    deallocation32(M, num_password/4);

    return (fine_elaborazione - inizio_elaborazione);
}

/********
 VERSIONE CON DISPOSIZIONE EFFICIENTE DEI DATI IN MEMORIA -> OPERAZIONE DI LOAD
********/

uint64_t md5_vettoriale_v3(password *array_password, unsigned int num_password, hash *array_hash){
    uint8_t **padded_password = padding_vettoriale(array_password, &num_password);
    uint32_t **M = initialization_v2_v3(padded_password, num_password);

    uint8_t i = 0;
    __m128i *p_K, *p_M;
    __m128i F;
    __m128i M_register;
    __m128i a0, A;
    __m128i b0, B;
    __m128i c0, C;
    __m128i d0, D;
    __m128i first_and, first_andnot;
    __m128i second_and, second_andnot;
    __m128i third_xor;
    __m128i fourth_xor, fourth_or;
    __m128i lo_a0_b0;
    __m128i hi_a0_b0;
    __m128i lo_c0_d0;
    __m128i hi_c0_d0;
    __m128i first_hash, first_hash_uns;
    __m128i second_hash, second_hash_uns;
    __m128i third_hash, third_hash_uns;
    __m128i fourth_hash, fourth_hash_uns;
    __m128i registro_1 = _mm_set1_epi8(-1); //maschera di 1 (si utilizza -1 in quanto la codifica in binario è pari a 1111 1111)

    uint64_t inizio_elaborazione = __rdtsc();

    //Le password vengono processate al passo di 4
    for(unsigned int k = 0; k < num_password/4; k++){
        p_K = (__m128i *)array_hash[k*4].hash;

        // I registeri A, B, C, D sono i registeri in cui avviene il calcolo -> assumono i valori iniziali dei registeri a0, b0, c0, d0
        A = a0_init;
        B = b0_init;
        C = c0_init;
        D = d0_init;

        p_M = (__m128i *) M[k];

        // 4 round di 16 operazioni
        for(i = 0; i < 16; i++){
            first_and = _mm_and_si128 (B, C);
            first_andnot = _mm_andnot_si128 (B, D);
            F = _mm_or_si128 (first_and, first_andnot);

            M_register = _mm_load_si128(p_M+i);
            
            F = _mm_add_epi32(_mm_add_epi32(A, F), _mm_add_epi32(K_register[i], M_register));            
            A = D;
            D = C;
            C = B;
            B = _mm_add_epi32(B, _mm_or_si128 (_mm_slli_epi32 (F, s[i]), _mm_srli_epi32 (F, 32-s[i])));
        }

        for(i = 16; i < 32; i++){
            second_and = _mm_and_si128 (D, B);
            second_andnot = _mm_andnot_si128 (D, C);
            F = _mm_or_si128 (second_and, second_andnot);

            M_register = _mm_load_si128(p_M+i);
            
            F = _mm_add_epi32(_mm_add_epi32(A, F), _mm_add_epi32(K_register[i], M_register));            
            A = D;
            D = C;
            C = B;
            B = _mm_add_epi32(B, _mm_or_si128 (_mm_slli_epi32 (F, s[i]), _mm_srli_epi32 (F, 32-s[i])));
        }

        for(i = 32; i < 48; i++){
            third_xor = _mm_xor_si128(B, C);
            F = _mm_xor_si128 (third_xor, D);

            M_register = _mm_load_si128(p_M+i);
            
            F = _mm_add_epi32(_mm_add_epi32(A, F), _mm_add_epi32(K_register[i], M_register));            
            A = D;
            D = C;
            C = B;
            B = _mm_add_epi32(B, _mm_or_si128 (_mm_slli_epi32 (F, s[i]), _mm_srli_epi32 (F, 32-s[i])));
        }

        for(i = 48; i < 64; i++){
            fourth_xor = _mm_xor_si128 (D, registro_1);
            fourth_or = _mm_or_si128 (B, fourth_xor);
            F = _mm_xor_si128 (C, fourth_or);

            M_register = _mm_load_si128(p_M+i);
            
            F = _mm_add_epi32(_mm_add_epi32(A, F), _mm_add_epi32(K_register[i], M_register));            
            A = D;
            D = C;
            C = B;
            B = _mm_add_epi32(B, _mm_or_si128 (_mm_slli_epi32 (F, s[i]), _mm_srli_epi32 (F, 32-s[i])));
        }

        // Fine elaborazione chunk -> aggiorno variabili
        A = _mm_add_epi32(a0_init, A);
        B = _mm_add_epi32(b0_init, B);
        C = _mm_add_epi32(c0_init, C);
        D = _mm_add_epi32(d0_init, D);

        // 4 hash calcolati ma i valori dell'hash sono su 4 registri differenti
        lo_a0_b0 = _mm_unpacklo_epi32(A, B);
        hi_a0_b0 = _mm_unpackhi_epi32(A, B);
        lo_c0_d0 = _mm_unpacklo_epi32(C, D);
        hi_c0_d0 = _mm_unpackhi_epi32(C, D);

        first_hash_uns = _mm_unpacklo_epi32(lo_a0_b0, lo_c0_d0);
        second_hash_uns = _mm_unpackhi_epi32(lo_a0_b0,lo_c0_d0);
        third_hash_uns = _mm_unpacklo_epi32(hi_a0_b0, hi_c0_d0);
        fourth_hash_uns = _mm_unpackhi_epi32(hi_a0_b0, hi_c0_d0);

        first_hash = _mm_shuffle_epi32(first_hash_uns, 216);
        second_hash = _mm_shuffle_epi32(second_hash_uns, 216);
        third_hash = _mm_shuffle_epi32(third_hash_uns, 216);
        fourth_hash = _mm_shuffle_epi32(fourth_hash_uns, 216);
        
        _mm_store_si128(p_K, first_hash);
        _mm_store_si128(p_K + 1, second_hash);
        _mm_store_si128(p_K + 2, third_hash);
        _mm_store_si128(p_K + 3, fourth_hash);
        
    }

    uint64_t fine_elaborazione = __rdtsc();
    
    deallocation8(padded_password, num_password);
    deallocation32(M, num_password/4);

    return (fine_elaborazione - inizio_elaborazione);
}