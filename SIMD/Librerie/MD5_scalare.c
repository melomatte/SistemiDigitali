#include "MD5_scalare.h"

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

uint64_t md5(password *array_password, unsigned int num_password, hash *array_hash, hash hash_tocrack, int modalita_test) {
    // Padding password
    // Assunzione di base -> tutte le password presentano una lunghezza minore di 64 caratteri (64 byte), ovvero sono costituite da un solo chunk
    uint32_t a0, A;
    uint32_t b0, B;
    uint32_t c0, C;
    uint32_t d0, D;
    uint32_t F;
    uint8_t **padded_password;
    uint64_t inizio_elaborazione, fine_elaborazione;
    bool sentinella;

    if(modalita_test == 1){
        inizio_elaborazione = __rdtsc();
        padded_password = padding_scalare(array_password, num_password);
    }else{
        padded_password = padding_scalare(array_password, num_password);
        inizio_elaborazione = __rdtsc();
    }

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

        // Confronta hash
        sentinella = true;
        for (int i = 0; i < 16; i++) {
            if (array_hash[k].hash[i] != hash_tocrack.hash[i]) {
                sentinella = false;
            }
        }

        if (sentinella) printf("L'hash corrisponde alla password: %s\n", array_password[k].pwd);
    }

    fine_elaborazione = __rdtsc();

    deallocation8(padded_password, num_password);

    return (fine_elaborazione - inizio_elaborazione);
}
