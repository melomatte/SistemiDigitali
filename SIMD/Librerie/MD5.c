#include "MD5.h"

void register_initialization(){
    for(int i = 0; i < 64; i++) K_register[i] = _mm_set1_epi32 (K[i]);

    a0_init = _mm_set1_epi32 (0x67452301);
    b0_init = _mm_set1_epi32 (0xefcdab89);
    c0_init = _mm_set1_epi32 (0x98badcfe);
    d0_init = _mm_set1_epi32 (0x10325476);
}

uint64_t md5(password *array_password, unsigned int num_password, hash *array_hash) {
    uint64_t inizio_elaborazione = __rdtsc();

    // Padding password
    // Assunzione di base -> tutte le password presentano una lunghezza minore di 64 caratteri (64 byte), ovvero sono costituite da un solo chunk
    uint8_t padded_password[num_password][64];
    for(unsigned int i = 0; i < num_password; i++){
        memcpy(padded_password[i], array_password[i].pwd, array_password[i].len_pwd);
        padded_password[i][array_password[i].len_pwd] = 0x80; // padded_password[0..len_password-1] = password; padded_password[len_password] = 1000 0000
        for (uint8_t j = array_password[i].len_pwd + 1; j < 56; j++) {    //padded_password[len_password+1..56] = 0000 0000
            padded_password[i][j] = 0x00;
        }
        uint64_t len_password_bits = array_password[i].len_pwd * 8; // len_password in bit
        memcpy(padded_password[i] + 56, &len_password_bits, 8); // padded_password[56..63] = len_password_bits
    }

    //Per ogni parola, viene preso in considerazione l'unico chunk da 64 byte
    for(unsigned int k = 0; k < num_password; k++){
        // Variabili iniziali MD5 (32 bit unsigned)
        uint32_t a0 = 0x67452301;
        uint32_t b0 = 0xefcdab89;
        uint32_t c0 = 0x98badcfe;
        uint32_t d0 = 0x10325476;

        // Il chunk viene diviso in elementi da 32 bit (64 byte -> 16 elementi da 32 bit)
        uint32_t *M = (uint32_t *)(padded_password[k]);

        // A, B, C, D assumono i valori iniziali delle variabili a0, b0, c0, d0
        uint32_t A = a0, B = b0, C = c0, D = d0;

        // 4 round di 16 operazioni
        for (uint16_t i = 0; i < 64; i++) {
            uint32_t F, g;
            //~ -> operatore bitwise NOT, inverte i bit (gli 0 diventano 1 e viceversa)
            //^ -> operatore XOR
            if (i <= 15) {
                F = (B & C) | (~B & D);
                g = i;
            } else if (i >= 16 && i <= 31) {
                F = (D & B) | (~D & C);
                g = (5 * i + 1) % 16;
            } else if (i >= 32 && i <= 47) {
                F = B ^ C ^ D;
                g = (3 * i + 5) % 16;
            } else {
                F = C ^ (B | ~D);
                g = (7 * i) % 16;
            }
                        
            F = A + F + K[i] + M[g];
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
    return fine_elaborazione - inizio_elaborazione;
}

uint64_t md5_vettoriale(password *array_password, unsigned int num_password, hash *array_hash){
    uint64_t inizio_elaborazione = __rdtsc();
    // Padding password
    // Assunzione di base -> tutte le password presentano una lunghezza minore di 64 caratteri (64 byte), ovvero sono costituite da un solo chunk
    
    //Per garantire più efficienza, si ha un pattern di memorizzazione differente per le password
    /*
    uint8_t temp[num_password][64];
    for(unsigned int i = 0; i < num_password; i++){
        memcpy(temp[i], array_password[i].pwd, array_password[i].len_pwd);
        temp[i][array_password[i].len_pwd] = 0x80;
        for (uint8_t j = array_password[i].len_pwd + 1; j < 56; j++) {  
            temp[i][j] = 0x00;
        }
        uint64_t len_password_bits = array_password[i].len_pwd * 8;
        memcpy(temp[i] + 56, &len_password_bits, 8);
    }
    uint8_t padded_password[num_password][64]__attribute__((aligned(16)));
    int cont = 0;
    for(unsigned int i = 0; i < num_password; i++){
        if (num_password%4==0) cont = 0;

        for(uint8_t j = 0; j < 4; j++){
            for(uint8_t v = 0; v < 4; v++){
                for(uint8_t k = 0; k < 4; k++){
                    padded_password[i][j*16+v*4+k] = temp[v+(i/4)*4][cont*16+j*4+k];
                }
            }
        }

        cont++;
    }*/

   uint8_t padded_password[num_password][64]__attribute__((aligned(16)));
    for(unsigned int i = 0; i < num_password; i++){
        memcpy(padded_password[i], array_password[i].pwd, array_password[i].len_pwd);
        padded_password[i][array_password[i].len_pwd] = 0x80; // padded_password[0..len_password-1] = password; padded_password[len_password] = 1000 0000
        for (uint8_t j = array_password[i].len_pwd + 1; j < 56; j++) {    //padded_password[len_password+1..56] = 0000 0000
            padded_password[i][j] = 0x00;
        }
        uint64_t len_password_bits = array_password[i].len_pwd * 8; // len_password in bit
        memcpy(padded_password[i] + 56, &len_password_bits, 8); // padded_password[56..63] = len_password_bits
    }

    __m128i F;
    uint8_t g;
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

    //Le password vengono processate al passo di 4
    for(unsigned int k = 0; k < num_password; k+=4){
        uint32_t (*M)[16] = (uint32_t (*)[16])(padded_password[k]);
        // Registri iniziali -> ogni registro contiene 4 elementi da 32 bit, tutti che assumono il valore di inizializzazione
        a0 = a0_init;
        b0 = b0_init;
        c0 = c0_init;
        d0 = d0_init;

        // I registeri A, B, C, D sono i registeri in cui avviene il calcolo -> assumono i valori iniziali dei registeri a0, b0, c0, d0
        A = a0, B = b0, C = c0, D = d0;

        // 4 round di 16 operazioni
        for (uint16_t i = 0; i < 64; i++) {
            if (i <= 15) {
                F = _mm_or_si128 (_mm_and_si128 (B, C), _mm_andnot_si128 (B, D));
                g = i;
            } else if (i >= 16 && i <= 31) {
                F = _mm_or_si128 (_mm_and_si128 (D, B), _mm_andnot_si128 (D, C));
                g = (5 * i + 1) % 16;
            } else if (i >= 32 && i <= 47) {
                F = _mm_xor_si128 (_mm_xor_si128(B, C), D);
                g = (3 * i + 5) % 16;
            } else {
                //Il NOT di un registro è stato ottenuto come XOR tra il registro e maschera di 1 (si utilizza -1 in quanto la codifica in binario è pari a 1111 1111)
                F = _mm_xor_si128 (C, _mm_or_si128 (B, _mm_xor_si128 (D, _mm_set1_epi8(-1))));
                g = (7 * i) % 16;
            }

            /*
            __m128i *p_M = (__m128i *)&padded_password[g/4+k][(g/4)*16];
            __m128i M_register = _mm_load_si128 (p_M);*/

            M_register = _mm_set_epi32 (M[k+3][g], M[k+2][g] , M[k+1][g], M[k][g]);

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

        _mm_storeu_si128((__m128i*) &array_hash[k].hash, _mm_shuffle_epi32(first_hash, 216));
        _mm_storeu_si128((__m128i*) &array_hash[k+1].hash, _mm_shuffle_epi32(second_hash, 216));
        _mm_storeu_si128((__m128i*) &array_hash[k+2].hash, _mm_shuffle_epi32(third_hash, 216));
        _mm_storeu_si128((__m128i*) &array_hash[k+3].hash, _mm_shuffle_epi32(fourth_hash, 216));
    }

    uint64_t fine_elaborazione = __rdtsc();
    return fine_elaborazione - inizio_elaborazione;
}