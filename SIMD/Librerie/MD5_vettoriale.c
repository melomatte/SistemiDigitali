#include "MD5_vettoriale.h"

__m128i K_register[64];
__m128i a0_init;
__m128i b0_init;
__m128i c0_init;
__m128i d0_init;

uint8_t** padding_vettoriale(password *array_password, unsigned int *num_password){
    unsigned int i;
    uint8_t diff, j, k;

    //Si controlla quante password mancano per arrivare al successivo multiplo di 4
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
        padded_password[i][array_password[i].len_pwd] = 0x80; 
        memset(padded_password[i] + array_password[i].len_pwd + 1, 0, 56 - array_password[i].len_pwd - 1);
        uint64_t len_password_bits = array_password[i].len_pwd * 8; 
        memcpy(padded_password[i] + 56, &len_password_bits, 8); 
    }

    //Si aggiungono delle password con bit a 0 per ottenere numero di password multiplo di 4
    for (k = 0; k < diff; k++) {
        for (j = 0; j < 64; j++) {
            padded_password[(*num_password) - diff + k][j] = 0x00;
        }
    }

    return padded_password;
}

/********
 VERSIONE VETTORIALE STANDARD
********/

void initialization(){
    unsigned int i;
    uint8_t j, k;
    uint32_t combo;

    //Inizializzazione dei registri
    for(int i = 0; i < 64; i++) K_register[i] = _mm_set1_epi32 (K[i]);

    a0_init = _mm_set1_epi32 (0x67452301);
    b0_init = _mm_set1_epi32 (0xefcdab89);
    c0_init = _mm_set1_epi32 (0x98badcfe);
    d0_init = _mm_set1_epi32 (0x10325476);
}

uint64_t md5_vettoriale(password *array_password, unsigned int num_password, uint8_t *hash_tocrack, int modalita_test){
    uint8_t i = 0;
    uint8_t **padded_password;
    uint32_t *M_0, *M_1, *M_2, *M_3;
    uint8_t hash_calcolato[4][16];
    __m128i *p_K = (__m128i *)hash_calcolato;
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
    __m128i first_hash, first_hash_uns;
    __m128i second_hash, second_hash_uns;
    __m128i third_hash, third_hash_uns;
    __m128i fourth_hash, fourth_hash_uns;
    __m128i registro_1 = _mm_set1_epi8(-1);                 //maschera di 1 (si utilizza -1 in quanto la codifica in binario è pari a 1111 1111)
    uint64_t inizio_elaborazione, fine_elaborazione;
    bool sentinella1, sentinella2, sentinella3, sentinella4;

    if(modalita_test == 1){
        inizio_elaborazione = __rdtsc();                                 
        padded_password = padding_vettoriale(array_password, &num_password);
        initialization();
    }else{
        padded_password = padding_vettoriale(array_password, &num_password);
        initialization();
        inizio_elaborazione = __rdtsc();
    }

    //Ogni ciclo elabora 4 password
    for(unsigned int k = 0; k < num_password/4; k++){
        //Registri di calcolo inizializzati al valore costante stabilito da algortimo MD5
        A = a0_init;
        B = b0_init;
        C = c0_init;
        D = d0_init;

        //4 puntatori per considerare le password paddate costituite da 16 elementi da 32 bit
        M_0 = (uint32_t *)padded_password[k*4];
        M_1 = (uint32_t *)padded_password[k*4+1];
        M_2 = (uint32_t *)padded_password[k*4+2];
        M_3 = (uint32_t *)padded_password[k*4+3];


        // 4 round di 16 operazioni
        for(i = 0; i < 16; i++){
            F = _mm_or_si128 (_mm_and_si128 (B, C),_mm_andnot_si128 (B, D));

            M_register = _mm_set_epi32(M_3[g[i]], M_2[g[i]], M_1[g[i]], M_0[g[i]]);
            
            F = _mm_add_epi32(_mm_add_epi32(A, F), _mm_add_epi32(K_register[i], M_register));            
            A = D;
            D = C;
            C = B;
            B = _mm_add_epi32(B, _mm_or_si128 (_mm_slli_epi32 (F, s[i]), _mm_srli_epi32 (F, 32-s[i])));
        }

        for(i = 16; i < 32; i++){
            F = _mm_or_si128 (_mm_and_si128 (D, B), _mm_andnot_si128 (D, C));

            M_register = _mm_set_epi32(M_3[g[i]], M_2[g[i]], M_1[g[i]], M_0[g[i]]);
            
            F = _mm_add_epi32(_mm_add_epi32(A, F), _mm_add_epi32(K_register[i], M_register));            
            A = D;
            D = C;
            C = B;
            B = _mm_add_epi32(B, _mm_or_si128 (_mm_slli_epi32 (F, s[i]), _mm_srli_epi32 (F, 32-s[i])));
        }

        for(i = 32; i < 48; i++){
            F = _mm_xor_si128 (_mm_xor_si128(B, C), D);

            M_register = _mm_set_epi32(M_3[g[i]], M_2[g[i]], M_1[g[i]], M_0[g[i]]);
            
            F = _mm_add_epi32(_mm_add_epi32(A, F), _mm_add_epi32(K_register[i], M_register));            
            A = D;
            D = C;
            C = B;
            B = _mm_add_epi32(B, _mm_or_si128 (_mm_slli_epi32 (F, s[i]), _mm_srli_epi32 (F, 32-s[i])));
        }

        for(i = 48; i < 64; i++){
            F = _mm_xor_si128 (C, _mm_or_si128 (B, _mm_xor_si128 (D, registro_1)));

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

        // Manipolazione registri 
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

        //Confronta hash
        sentinella1 = true;
        sentinella2 = true;
        sentinella3 = true;
        sentinella4 = true;

        for (int i = 0; i < 16; i++) {
            if (hash_calcolato[0][i] != hash_tocrack[i]) {
                sentinella1 = false;
            }
            if (hash_calcolato[1][i] != hash_tocrack[i]) {
                sentinella2 = false;
            }
            if (hash_calcolato[2][i] != hash_tocrack[i]) {
                sentinella3 = false;
            }
            if (hash_calcolato[3][i] != hash_tocrack[i]) {
                sentinella4 = false;
            }
        }

        if(sentinella1){
            printf("L'hash corrisponde alla password: %s\n", array_password[k*4].pwd);
        }else if(sentinella2){
            printf("L'hash corrisponde alla password: %s\n", array_password[k*4+1].pwd);
        }else if(sentinella3){
            printf("L'hash corrisponde alla password: %s\n", array_password[k*4+2].pwd);
        }else if(sentinella4){
            printf("L'hash corrisponde alla password: %s\n", array_password[k*4+3].pwd);
        }
     
    }

    fine_elaborazione = __rdtsc();
    
    deallocation8(padded_password, num_password);

    return (fine_elaborazione - inizio_elaborazione);
}

/********
 VERSIONI CON DISPOSIZIONE DIFFERENTE DELLE PADDED PASSWORD IN MEMORIA (SALVATI ALL'INTERNO DI REGISTRI ESTESI) -> POSSIBILE OVERHEAD DEI REGISTRI
********/

//PADDED PASSWORD SALVATE IN REGISTRI VETTORIALI -> POSSIBILE OVERHEAD DEI REGISTRI

__m128i** initialization_v1(uint8_t** padded_password, unsigned int num_password){
    unsigned int i;
    uint8_t j, k;
    uint32_t combo;

    //Inizializzazione dei registri
    for(int i = 0; i < 64; i++) K_register[i] = _mm_set1_epi32 (K[i]);

    a0_init = _mm_set1_epi32 (0x67452301);
    b0_init = _mm_set1_epi32 (0xefcdab89);
    c0_init = _mm_set1_epi32 (0x98badcfe);
    d0_init = _mm_set1_epi32 (0x10325476);

    //Disposizione contigua delle padded password in memoria
    uint32_t **M = (uint32_t **) _mm_malloc(num_password/4 * sizeof(uint32_t *), 16);
    for(i = 0; i < num_password/4; i++){
        M[i] = (uint32_t *) _mm_malloc(64*4*sizeof(uint32_t), 16);
    }

    __m128i **M_register = (__m128i **) _mm_malloc(num_password/4 * sizeof(__m128i *), 16);
    for(i = 0; i < num_password/4; i++){
        M_register[i] = (__m128i *) _mm_malloc(16*4*sizeof(__m128i), 16);
    }

    __m128i* p_M;

    for(i = 0; i < num_password/4; i++){
        p_M = (__m128i *) M[i];
        for(j = 0; j < 16; j++){
            for(k = 0; k < 4; k++){
                combo = (uint32_t)(padded_password[i * 4 + k][j * 4]) |
                        (uint32_t)(padded_password[i * 4 + k][j * 4 + 1]) << 8 |
                        (uint32_t)(padded_password[i * 4 + k][j * 4 + 2]) << 16 |
                        (uint32_t)(padded_password[i * 4 + k][j * 4 + 3]) << 24;
                M[i][j*4+k] = combo;
            }
            M_register[i][j] = _mm_load_si128(p_M+j);
        }
    }

    deallocation32(M,num_password/4);

    return M_register;
}

uint64_t md5_vettoriale_v1(password *array_password, unsigned int num_password, uint8_t* hash_tocrack, int modalita_test){
    __m128i** M_register;
    uint8_t i = 0;
    uint8_t **padded_password;
    uint8_t hash_calcolato[4][16];
    __m128i *p_K = (__m128i *)hash_calcolato;
    __m128i F;
    __m128i a0, A;
    __m128i b0, B;
    __m128i c0, C;
    __m128i d0, D;
    __m128i lo_a0_b0;
    __m128i hi_a0_b0;
    __m128i lo_c0_d0;
    __m128i hi_c0_d0;
    __m128i first_hash, first_hash_uns;
    __m128i second_hash, second_hash_uns;
    __m128i third_hash, third_hash_uns;
    __m128i fourth_hash, fourth_hash_uns;
    __m128i registro_1 = _mm_set1_epi8(-1);                                 //maschera di 1 (si utilizza -1 in quanto la codifica in binario è pari a 1111 1111)
    bool sentinella1, sentinella2, sentinella3, sentinella4;
    uint64_t inizio_elaborazione, fine_elaborazione;

    if(modalita_test == 1){
        inizio_elaborazione = __rdtsc();                                 
        padded_password = padding_vettoriale(array_password, &num_password);
        M_register = initialization_v1(padded_password, num_password);
    }else{
        padded_password = padding_vettoriale(array_password, &num_password);
        M_register = initialization_v1(padded_password, num_password);
        inizio_elaborazione = __rdtsc();
    }


    //Ogni ciclo elabora 4 password
    for(unsigned int k = 0; k < num_password/4; k++){
        //Registri di calcolo inizializzati al valore costante stabilito da algortimo MD5
        A = a0_init;
        B = b0_init;
        C = c0_init;
        D = d0_init;

        // 4 round di 16 operazioni
        for(i = 0; i < 16; i++){
            F = _mm_or_si128 (_mm_and_si128 (B, C),_mm_andnot_si128 (B, D));
            
            F = _mm_add_epi32(_mm_add_epi32(A, F), _mm_add_epi32(K_register[i], M_register[k][g[i]]));            
            A = D;
            D = C;
            C = B;
            B = _mm_add_epi32(B, _mm_or_si128 (_mm_slli_epi32 (F, s[i]), _mm_srli_epi32 (F, 32-s[i])));
        }

        for(i = 16; i < 32; i++){
            F = _mm_or_si128 (_mm_and_si128 (D, B), _mm_andnot_si128 (D, C));

            F = _mm_add_epi32(_mm_add_epi32(A, F), _mm_add_epi32(K_register[i], M_register[k][g[i]]));            
            A = D;
            D = C;
            C = B;
            B = _mm_add_epi32(B, _mm_or_si128 (_mm_slli_epi32 (F, s[i]), _mm_srli_epi32 (F, 32-s[i])));
        }

        for(i = 32; i < 48; i++){
            F = _mm_xor_si128 (_mm_xor_si128(B, C), D);

            F = _mm_add_epi32(_mm_add_epi32(A, F), _mm_add_epi32(K_register[i], M_register[k][g[i]]));            
            A = D;
            D = C;
            C = B;
            B = _mm_add_epi32(B, _mm_or_si128 (_mm_slli_epi32 (F, s[i]), _mm_srli_epi32 (F, 32-s[i])));
        }

        for(i = 48; i < 64; i++){
            F = _mm_xor_si128 (C, _mm_or_si128 (B, _mm_xor_si128 (D, registro_1)));

            F = _mm_add_epi32(_mm_add_epi32(A, F), _mm_add_epi32(K_register[i], M_register[k][g[i]]));            
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

        // Manipolazione registri 
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

        // Confronta hash
        sentinella1 = true;
        sentinella2 = true;
        sentinella3 = true;
        sentinella4 = true;

        for (int i = 0; i < 16; i++) {
            if (hash_calcolato[0][i] != hash_tocrack[i]) {
                sentinella1 = false;
            }
            if (hash_calcolato[1][i] != hash_tocrack[i]) {
                sentinella2 = false;
            }
            if (hash_calcolato[2][i] != hash_tocrack[i]) {
                sentinella3 = false;
            }
            if (hash_calcolato[3][i] != hash_tocrack[i]) {
                sentinella4 = false;
            }
        }

        if(sentinella1){
            printf("L'hash corrisponde alla password: %s\n", array_password[k*4].pwd);
        }else if(sentinella2){
            printf("L'hash corrisponde alla password: %s\n", array_password[k*4+1].pwd);
        }else if(sentinella3){
            printf("L'hash corrisponde alla password: %s\n", array_password[k*4+2].pwd);
        }else if(sentinella4){
            printf("L'hash corrisponde alla password: %s\n", array_password[k*4+3].pwd);
        }
        
    }

    fine_elaborazione = __rdtsc();
    
    deallocation8(padded_password, num_password);

    for (unsigned int i = 0; i < num_password/4; i++) {
            _mm_free(M_register[i]);
    }
    _mm_free(M_register);

    return (fine_elaborazione - inizio_elaborazione);
}

//OPERAZIONE DI SET DELLE PADDED PASSWORD ALL'INTERNO DEL REGISTRO VETTORIALE

uint32_t** initialization_v2_v3(uint8_t** padded_password, unsigned int num_password){
    unsigned int i;
    uint8_t j, k;
    uint32_t combo;

    //Inizializzazione dei registri
    for(int i = 0; i < 64; i++) K_register[i] = _mm_set1_epi32 (K[i]);

    a0_init = _mm_set1_epi32 (0x67452301);
    b0_init = _mm_set1_epi32 (0xefcdab89);
    c0_init = _mm_set1_epi32 (0x98badcfe);
    d0_init = _mm_set1_epi32 (0x10325476);

    //Disposizione contigua delle padded password in memoria
    uint32_t **M = (uint32_t **) _mm_malloc(num_password/4 * sizeof(uint32_t *), 16);
    for(i = 0; i < num_password/4; i++){
        M[i] = (uint32_t *) _mm_malloc(16*4*sizeof(uint32_t), 16);
    }

    for(i = 0; i < num_password/4; i++){
        for(j = 0; j < 16; j++){
            for(k = 0; k < 4; k++){
                combo = (uint32_t)(padded_password[i * 4 + k][j * 4]) |
                        (uint32_t)(padded_password[i * 4 + k][j * 4 + 1]) << 8 |
                        (uint32_t)(padded_password[i * 4 + k][j * 4 + 2]) << 16 |
                        (uint32_t)(padded_password[i * 4 + k][j * 4 + 3]) << 24;
                M[i][j*4+k] = combo;
            }
        }
    }

    return M;
 
}

uint64_t md5_vettoriale_v2(password *array_password, unsigned int num_password, uint8_t *hash_tocrack, int modalita_test){
    uint8_t i = 0;
    uint8_t hash_calcolato[4][16];
    __m128i *p_K = (__m128i *)hash_calcolato;
    uint8_t **padded_password;
    uint32_t **M;
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
    __m128i first_hash, first_hash_uns;
    __m128i second_hash, second_hash_uns;
    __m128i third_hash, third_hash_uns;
    __m128i fourth_hash, fourth_hash_uns;
    __m128i registro_1 = _mm_set1_epi8(-1); //maschera di 1 (si utilizza -1 in quanto la codifica in binario è pari a 1111 1111)
    bool sentinella1, sentinella2, sentinella3, sentinella4;
    uint64_t inizio_elaborazione, fine_elaborazione;

    if(modalita_test == 1){
        inizio_elaborazione = __rdtsc();                                 
        padded_password = padding_vettoriale(array_password, &num_password);
        M = initialization_v2_v3(padded_password, num_password);
    }else{
        padded_password = padding_vettoriale(array_password, &num_password);
        M = initialization_v2_v3(padded_password, num_password);
        inizio_elaborazione = __rdtsc();
    }

    //Ogni ciclo elabora 4 password
    for(unsigned int k = 0; k < num_password/4; k++){
        //Registri di calcolo inizializzati al valore costante stabilito da algortimo MD5
        A = a0_init;
        B = b0_init;
        C = c0_init;
        D = d0_init;

        // 4 round di 16 operazioni
        for(i = 0; i < 16; i++){
            F = _mm_or_si128 (_mm_and_si128 (B, C),_mm_andnot_si128 (B, D));

            M_register = _mm_set_epi32(M[k][g[i]*4+3], M[k][g[i]*4+2], M[k][g[i]*4+1], M[k][g[i]*4]);
            
            F = _mm_add_epi32(_mm_add_epi32(A, F), _mm_add_epi32(K_register[i], M_register));            
            A = D;
            D = C;
            C = B;
            B = _mm_add_epi32(B, _mm_or_si128 (_mm_slli_epi32 (F, s[i]), _mm_srli_epi32 (F, 32-s[i])));
        }

        for(i = 16; i < 32; i++){
            F = _mm_or_si128 (_mm_and_si128 (D, B), _mm_andnot_si128 (D, C));

            M_register = _mm_set_epi32(M[k][g[i]*4+3], M[k][g[i]*4+2], M[k][g[i]*4+1], M[k][g[i]*4]);
            
            F = _mm_add_epi32(_mm_add_epi32(A, F), _mm_add_epi32(K_register[i], M_register));            
            A = D;
            D = C;
            C = B;
            B = _mm_add_epi32(B, _mm_or_si128 (_mm_slli_epi32 (F, s[i]), _mm_srli_epi32 (F, 32-s[i])));
        }

        for(i = 32; i < 48; i++){
            F = _mm_xor_si128 (_mm_xor_si128(B, C), D);

            M_register = _mm_set_epi32(M[k][g[i]*4+3], M[k][g[i]*4+2], M[k][g[i]*4+1], M[k][g[i]*4]);
            
            F = _mm_add_epi32(_mm_add_epi32(A, F), _mm_add_epi32(K_register[i], M_register));            
            A = D;
            D = C;
            C = B;
            B = _mm_add_epi32(B, _mm_or_si128 (_mm_slli_epi32 (F, s[i]), _mm_srli_epi32 (F, 32-s[i])));
        }

        for(i = 48; i < 64; i++){
            F = _mm_xor_si128 (C, _mm_or_si128 (B, _mm_xor_si128 (D, registro_1)));

            M_register = _mm_set_epi32(M[k][g[i]*4+3], M[k][g[i]*4+2], M[k][g[i]*4+1], M[k][g[i]*4]);
            
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

        // Manipolazione registri 
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

        // Confronta hash
        sentinella1 = true;
        sentinella2 = true;
        sentinella3 = true;
        sentinella4 = true;

        for (int i = 0; i < 16; i++) {
            if (hash_calcolato[0][i] != hash_tocrack[i]) {
                sentinella1 = false;
            }
            if (hash_calcolato[1][i] != hash_tocrack[i]) {
                sentinella2 = false;
            }
            if (hash_calcolato[2][i] != hash_tocrack[i]) {
                sentinella3 = false;
            }
            if (hash_calcolato[3][i] != hash_tocrack[i]) {
                sentinella4 = false;
            }
        }

        if(sentinella1){
            printf("L'hash corrisponde alla password: %s\n", array_password[k*4].pwd);
        }else if(sentinella2){
            printf("L'hash corrisponde alla password: %s\n", array_password[k*4+1].pwd);
        }else if(sentinella3){
            printf("L'hash corrisponde alla password: %s\n", array_password[k*4+2].pwd);
        }else if(sentinella4){
            printf("L'hash corrisponde alla password: %s\n", array_password[k*4+3].pwd);
        }
        
    }

    fine_elaborazione = __rdtsc();
    
    deallocation8(padded_password, num_password);
    deallocation32(M, num_password/4);

    return (fine_elaborazione - inizio_elaborazione);
}

//OPERAZIONE DI LOAD DELLE PADDED PASSWORD ALL'INTERNO DEL REGISTRO VETTORIALE

uint64_t md5_vettoriale_v3(password *array_password, unsigned int num_password, uint8_t *hash_tocrack, int modalita_test){
    uint8_t i = 0;
    uint8_t **padded_password;
    uint32_t **M;
    uint8_t hash_calcolato[4][16];
    __m128i *p_K = (__m128i *)hash_calcolato, *p_M;
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
    __m128i first_hash, first_hash_uns;
    __m128i second_hash, second_hash_uns;
    __m128i third_hash, third_hash_uns;
    __m128i fourth_hash, fourth_hash_uns;
    __m128i registro_1 = _mm_set1_epi8(-1); //maschera di 1 (si utilizza -1 in quanto la codifica in binario è pari a 1111 1111)
    bool sentinella1, sentinella2, sentinella3, sentinella4;
    uint64_t inizio_elaborazione, fine_elaborazione;

    if(modalita_test == 1){
        inizio_elaborazione = __rdtsc();                                 
        padded_password = padding_vettoriale(array_password, &num_password);
        M = initialization_v2_v3(padded_password, num_password);
    }else{
        padded_password = padding_vettoriale(array_password, &num_password);
        M = initialization_v2_v3(padded_password, num_password);
        inizio_elaborazione = __rdtsc();
    }

    //Ogni ciclo elabora 4 password
    for(unsigned int k = 0; k < num_password/4; k++){
        //Registri di calcolo inizializzati al valore costante stabilito da algortimo MD5
        A = a0_init;
        B = b0_init;
        C = c0_init;
        D = d0_init;

        p_M = (__m128i *) M[k];

        // 4 round di 16 operazioni
        for(i = 0; i < 16; i++){
            F = _mm_or_si128 (_mm_and_si128 (B, C),_mm_andnot_si128 (B, D));

            M_register = _mm_load_si128(p_M+g[i]);
            
            F = _mm_add_epi32(_mm_add_epi32(A, F), _mm_add_epi32(K_register[i], M_register));            
            A = D;
            D = C;
            C = B;
            B = _mm_add_epi32(B, _mm_or_si128 (_mm_slli_epi32 (F, s[i]), _mm_srli_epi32 (F, 32-s[i])));
        }

        for(i = 16; i < 32; i++){
            F = _mm_or_si128 (_mm_and_si128 (D, B), _mm_andnot_si128 (D, C));

            M_register = _mm_load_si128(p_M+g[i]);
            
            F = _mm_add_epi32(_mm_add_epi32(A, F), _mm_add_epi32(K_register[i], M_register));            
            A = D;
            D = C;
            C = B;
            B = _mm_add_epi32(B, _mm_or_si128 (_mm_slli_epi32 (F, s[i]), _mm_srli_epi32 (F, 32-s[i])));
        }

        for(i = 32; i < 48; i++){
            F = _mm_xor_si128 (_mm_xor_si128(B, C), D);

            M_register = _mm_load_si128(p_M+g[i]);
            
            F = _mm_add_epi32(_mm_add_epi32(A, F), _mm_add_epi32(K_register[i], M_register));            
            A = D;
            D = C;
            C = B;
            B = _mm_add_epi32(B, _mm_or_si128 (_mm_slli_epi32 (F, s[i]), _mm_srli_epi32 (F, 32-s[i])));
        }

        for(i = 48; i < 64; i++){
            F = _mm_xor_si128 (C, _mm_or_si128 (B, _mm_xor_si128 (D, registro_1)));

            M_register = _mm_load_si128(p_M+g[i]);
            
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

        // Manipolazione registri 
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

        // Confronta hash
        sentinella1 = true;
        sentinella2 = true;
        sentinella3 = true;
        sentinella4 = true;

        for (int i = 0; i < 16; i++) {
            if (hash_calcolato[0][i] != hash_tocrack[i]) {
                sentinella1 = false;
            }
            if (hash_calcolato[1][i] != hash_tocrack[i]) {
                sentinella2 = false;
            }
            if (hash_calcolato[2][i] != hash_tocrack[i]) {
                sentinella3 = false;
            }
            if (hash_calcolato[3][i] != hash_tocrack[i]) {
                sentinella4 = false;
            }
        }

        if(sentinella1){
            printf("L'hash corrisponde alla password: %s\n", array_password[k*4].pwd);
        }else if(sentinella2){
            printf("L'hash corrisponde alla password: %s\n", array_password[k*4+1].pwd);
        }else if(sentinella3){
            printf("L'hash corrisponde alla password: %s\n", array_password[k*4+2].pwd);
        }else if(sentinella4){
            printf("L'hash corrisponde alla password: %s\n", array_password[k*4+3].pwd);
        }
        
    }

    fine_elaborazione = __rdtsc();
    
    deallocation8(padded_password, num_password);
    deallocation32(M, num_password/4);

    return (fine_elaborazione - inizio_elaborazione);
}
