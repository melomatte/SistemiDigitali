#include "wordlist.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <cuda_runtime.h>

// Costanti per algoritmo MD5 -> lato CPU
static const uint32_t K_cpu[] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

static const uint8_t s_cpu[] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

static const uint8_t g_cpu[] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 1, 
    6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 5, 
    8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2, 0, 
    7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9 
};

static const uint32_t a0_cpu = 0x67452301;
static const uint32_t b0_cpu = 0xefcdab89;
static const uint32_t c0_cpu = 0x98badcfe;
static const uint32_t d0_cpu  = 0x10325476;

// Costanti per algoritmo MD5 -> lato GPU
__costant__ uint32_t K[64];
__costant__ uint8_t s[64];
__costant__ uint8_t g[64];
__costant__ uint32_t a0, b0, c0, d0;

#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))

__global__ void hashcracking (password *array_password ,uint8_t num_password, uint8_t *hash_da_craccare){
  uint8_t padded_password[num_password][64], hash_calcolato[16];
  uint8_t i,j;
  uint32_t *M;
  uint32_t A, B, C, D, F;
  uint64_t len_password_bits;

  //Padding delle password assegnate al thread

  // Assunzione di base -> tutte le password presentano una lunghezza minore di 64 caratteri (64 byte), ovvero sono costituite da un solo chunk
  for(i = 0; i < num_password; i++){
      memcpy(padded_password[i], array_password[i].pwd, array_password[i].len_pwd);
      padded_password[i][array_password[i].len_pwd] = 0x80;
      for (j = array_password[i].len_pwd + 1; j < 56; j++) {
          padded_password[i][j] = 0x00;
      }
      len_password_bits = array_password[i].len_pwd * 8;
      memcpy(padded_password[i] + 56, &len_password_bits, 8);
  }
  
  //Per ogni parola, viene preso in considerazione l'unico chunk da 64 byte
  for(i = 0; i < num_password; i++){
    // Il chunk viene diviso in elementi da 32 bit (64 byte -> 16 elementi da 32 bit)
    M = (uint32_t *)(padded_password[k]);

    // A, B, C, D assumono i valori iniziali delle variabili a0, b0, c0, d0
    A = a0, B = b0, C = c0, D = d0;

    // 4 round di 16 operazioni
    for (j = 0; j < 64; j++) {
        if (j <= 15) {
            F = (B & C) | (~B & D);
        } else if (j >= 16 && j <= 31) {
            F = (D & B) | (~D & C);
        } else if (j >= 32 && j <= 47) {
            F = B ^ C ^ D;
        } else {
            F = C ^ (B | ~D);
        }
                    
        F = A + F + K[j] + M[g[j]];
        A = D;
        D = C;
        C = B;
        B = B + LEFTROTATE(F, s[j]);
    }
      
    // Fine elaborazione chunk -> aggiorno variabili
    A += a0;
    B += b0;
    C += c0;
    D += d0;

    // hash -> insieme delle 4 variabili a 32 bit
    memcpy(hash_calcolato, &A, 4);
    memcpy(hash_calcolato + 4, &B, 4);
    memcpy(hash_calcolato + 8, &C, 4);
    memcpy(hash_calcolato + 12, &D, 4);

    //Confronto per verificare l'hash
    if(strcmp(hash_calcolato, hash_da_craccare) == 0) printf("L'hash corrisponde alla passsword %s\n", array_password[i]);

  }

}


int main(int argc, char *argv[]) {
    //Controllo numero argomenti
    if(argc != 3){
        perror("ERRORE-Il numero di parametri passati in ingresso al programmaè diverso da 2\n");
        perror("Usage: [wordlist] [hash MD5]\n");
        exit(-1);
    }

    //Lettura della wordlist
    result_wordlist wordlist = read_wordlist(argv[1]);

    if(wordlist.error_code == -1){
        perror("ERRORE-La __m128i*) &array_hash[k].hashwordlist non esiste o non è un file .txt\n");
        perror("Usage: [wordlist] [hash MD5]\n");
    }else if(wordlist.error_code == -2){
        perror("ERRORE-La wordlist contiene delle password con una lunghezza maggiore di 56 caratteri\n");
        perror("Usage: [wordlist] [hash MD5]\n");
    }else{
        /**********
        Dimensionamento di blocco e griglia -> blocco 1D e griglia 1D
        **********/

        dim3 blockSize(256);        
        int dimGrid = (len(wordlisit.num_password) + blockSize - 1) / blockSize;
        dim3 gridSize(dimGrid);

        /**********
        Passaggio valori al device
        **********/

        //Costanti per algortimo MD5
        cudaMemcpyToSymbol(K, K_cpu, 64*sizeof(uint32_t));
        cudaMemcpyToSymbol(s, s_cpu, 64*sizeof(uint8_t));
        cudaMemcpyToSymbol(g, g_cpu, 64*sizeof(uint8_t));
        cudaMemcpyToSymbol(a0, a0_cpu, sizeof(uint8_t));
        cudaMemcpyToSymbol(b0, b0_cpu, sizeof(uint8_t));
        cudaMemcpyToSymbol(c0, c0_cpu, sizeof(uint8_t));
        cudaMemcpyToSymbol(d0, d0_cpu, sizeof(uint8_t));

        //Password lette dalla wordlist e hash da craccare
        
        //Modalità di trasferimento normale
        password* d_array_password;
        uint8_t* d_hash_craccare;

        cudaMalloc(&d_array_password, sizeof(password)*wordlist.num_password);
        cudaMalloc(&d_hash_craccare, sizeof(uint8_t)*16);

        cudaMemcpy(d_array_password, wordlist.array_password, sizeof(password)*wordlist.num_password ,cudaMemcpyHostToDevice);
        cudaMemcpy(d_hash_craccare, argv[2], sizeof(uint8_t)*16, cudaMemcpyHostToDevice)

        hashcracking <<<gridSize, blockSize>>> (d_array_password, 1, d_hash_craccare);

        //Modalità pinned -> trasferimento più veloce per grandi quantità di dati
        cudaMallocHost(&d_array_password, sizeof(password)*wordlist.num_password);
        cudaMalloc(&d_hash_craccare, sizeof(uint8_t)*16);

        cudaMemcpy(d_array_password, wordlist.array_password, sizeof(password)*wordlist.num_password ,cudaMemcpyHostToDevice);
        cudaMemcpy(d_hash_craccare, argv[2], sizeof(uint8_t)*16, cudaMemcpyHostToDevice)

        hashcracking <<<gridSize, blockSize>>> (d_array_password, 1, d_hash_craccare);

        //Modalità UVA (unified virtual addressing) -> stesso spazio di indirizzamento virtuale (si possono utilizzare gli stessi puntatori tra host e device)
        

        //Modalità UM (unified memory) -> la gestione della memoria è responsabilità del cuda runtime, che può allocare i dati sulla memoria host o device (poco controllo)
        cudaMallocManaged(d_array_password, sizeof(password)*wordlist.num_password, 0);
        cudaMalloc(&d_hash_craccare, sizeof(uint8_t)*16);

        hashcracking <<<gridSize, blockSize>>> (d_array_password, 1, d_hash_craccare);

        /**********
        Lancio del kernel e sincronizzazione con il device
        **********/
        cudaDeviceSyncronize();

        //Necessari per trasferimento normale e pinned
        cudaFree(d_array_password);
        cudaFree(d_hash_craccare);

        printf("Termine dell'applicazione\n");

    }

    free(wordlist.array_password);

    return 0;
}
