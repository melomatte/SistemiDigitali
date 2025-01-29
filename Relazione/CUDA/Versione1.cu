#include "wordlist.h"
#include "wordlist.c"
#include "utils.c"
#include "utils.h"

//BEST VERSION

// Costanti per algoritmo MD5 -> lato GPU
__constant__ uint32_t K[64];
__constant__ uint8_t s[64];
__constant__ uint8_t g[64];
__constant__ uint32_t a0, b0, c0, d0;
__constant__ uint8_t hash_tocrack[16];

__global__ void hashcracking(password *array_password, uint8_t num_password, uint32_t tot_password) {
uint8_t hash_calcolato[16];
uint8_t padded_password[64];
uint32_t A, B, C, D, F;
uint32_t *M;
uint64_t len_password_bits;
bool sentinella;
int idx, start_idx, end_idx, i;

idx = blockIdx.x * blockDim.x + threadIdx.x; // Indice globale
if (idx >= tot_password) return;            // Esci se fuori range

start_idx = idx * num_password;                         // Inizio range
end_idx = min(start_idx + num_password, tot_password); // Fine range

// Ciclo per ogni password del range
for (int pw_idx = start_idx; pw_idx < end_idx; pw_idx++) {
    if (pw_idx >= tot_password) return;

    memcpy(padded_password, array_password[pw_idx].pwd, array_password[pw_idx].len_pwd);
    padded_password[array_password[pw_idx].len_pwd] = 0x80; // padded_password[0..len_password-1] = password; padded_password[len_password] = 1000 0000
    memset(padded_password + array_password[pw_idx].len_pwd +1, 0, 56 - array_password[pw_idx].len_pwd - 1);
    len_password_bits = array_password[pw_idx].len_pwd * 8;
    memcpy(padded_password + 56, &len_password_bits, 8);

    // Dividi il chunk in array di uint32_t
      M = (uint32_t *)(padded_password);
    A = a0, B = b0, C = c0, D = d0;

    // Esegui i 4 round
    for (i = 0; i < 64; i++) {
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

    // Aggiorna variabili
    A += a0;
    B += b0;
    C += c0;
    D += d0;

    // Calcola hash
    memcpy(hash_calcolato, &A, 4);
    memcpy(hash_calcolato + 4, &B, 4);
    memcpy(hash_calcolato + 8, &C, 4);
    memcpy(hash_calcolato + 12, &D, 4);

    // Confronta hash
    sentinella = true;
    for (int i = 0; i < 16; i++) {
        if (hash_calcolato[i] != hash_tocrack[i]) {
            sentinella = false;
        }
    }

    if (sentinella) printf("L'hash corrisponde alla password: %s\n", array_password[pw_idx].pwd);
}
    return;
}


int main(int argc, char *argv[]) {
    //Controllo numero argomenti
    if(argc != 3){
        perror("ERRORE-Il numero di parametri passati in ingresso al programmaè diverso da 2\n");
        perror("Usage: [wordlist] [hash MD5]\n");
        exit(-1);
    }

    if(!hash_valid(argv[2])){
        perror("ERRORE-L'hash fornito non è valido\n");
        perror("Usage: [wordlist] [hash MD5]\n");
        exit(-2);
    }

    //Lettura wordlist
    result_wordlist wordlist = read_wordlist(argv[1]);

    if(wordlist.error_code == -1){
        perror("ERRORE-La wordlist non esiste o non è un file .txt\n");
        perror("Usage: [wordlist] [hash MD5]\n");
        exit(-3);
    }else if(wordlist.error_code == -2){
        perror("ERRORE-La wordlist contiene delle password con una lunghezza maggiore di 56 caratteri\n");
        perror("Usage: [wordlist] [hash MD5]\n");
        exit(-4);
    }else{
        uint8_t h_hash_tocrack[16];
        password *d_array_password;
        uint8_t high_value, low_value;

        //DIMENSIONAMENTO GRIGLIA E BLOCCHI 
        dim3 blockSize(128);
        int dimGrid = (wordlist.num_password + blockSize.x - 1) / blockSize.x;
        dim3 gridSize(dimGrid);

        //TRASFERIMENTO DATI A GPU

        //Costanti per algortimo md5 + hash_tocrack
        CHECK(cudaMemcpyToSymbol(K, K_cpu, 64*sizeof(uint32_t)));
        CHECK(cudaMemcpyToSymbol(s, s_cpu, 64*sizeof(uint8_t)));
        CHECK(cudaMemcpyToSymbol(g, g_cpu, 64*sizeof(uint8_t)));
        CHECK(cudaMemcpyToSymbol(a0, &a0_cpu, sizeof(uint32_t)));
        CHECK(cudaMemcpyToSymbol(b0, &b0_cpu, sizeof(uint32_t)));
        CHECK(cudaMemcpyToSymbol(c0, &c0_cpu, sizeof(uint32_t)));
        CHECK(cudaMemcpyToSymbol(d0, &d0_cpu, sizeof(uint32_t)));

        for (int i = 0; i < 16; i++) {
          high_value = hex_char_to_value(argv[2][i * 2]);
          low_value = hex_char_to_value(argv[2][i * 2 + 1]);
          h_hash_tocrack[i] = (high_value << 4) | low_value;
        }

        CHECK(cudaMemcpyToSymbol(hash_tocrack, &h_hash_tocrack, sizeof(uint8_t)*16));

        //Wordlist
        /* MEMORIA GLOBALE */
        size_t password_size = wordlist.num_password * sizeof(password);

        CHECK(cudaMalloc((void **)&d_array_password, password_size)); // Allocazione della memoria sulla GPU
        CHECK(cudaMemcpy(d_array_password, wordlist.array_password, password_size, cudaMemcpyHostToDevice));
        cudaFuncSetAttribute(hashcracking, cudaFuncAttributePreferredSharedMemoryCarveout, 50);
        hashcracking <<<gridSize, blockSize, 16*sizeof(uint32_t)*blockSize.x>>> (d_array_password, 1, wordlist.num_password);

        CHECK(cudaDeviceSynchronize());
        cudaFree(d_array_password);
    }
	
    free(wordlist.array_password);

    return 0;
}
