#include "wordlist.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <cuda_runtime.h>

#define CHECK(call) \
{ \
    const cudaError_t error = call; \
    if (error != cudaSuccess) \
    { \
        printf("Error: %s:%d, ", __FILE__, __LINE__); \
        printf("code: %d, reason: %s\n", error, cudaGetErrorString(error)); \
        exit(1); \
    } \
}

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
__constant__ uint32_t K[64];
__constant__ uint8_t s[64];
__constant__ uint8_t g[64];
__constant__ uint32_t a0, b0, c0, d0;

#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))

__global__ void hashcracking (password *array_password ,uint8_t num_password, uint8_t *hash_da_craccare){
uint8_t padded_password[64], hash_calcolato[16];
uint8_t i,j;
uint32_t *M;
uint32_t A, B, C, D, F;
uint64_t len_password_bits;

int idx = blockIdx.x * blockDim.x + threadIdx.x;
int start_idx = idx * num_password;      // Indice iniziale delle password per il thread
int end_idx = min(start_idx + num_password, tot_password); // Limite superiore per il thread


//Padding delle password assegnate al thread
// Assunzione di base -> tutte le password presentano una lunghezza minore di 64 caratteri (64 byte), ovvero sono costituite da un solo chunk


for (int pw_idx = start_idx; pw_idx < end_idx; pw_idx++) {
  if (pw_idx >= tot_password) return;


  memcpy(padded_password, array_password[pw_idx].pwd, array_password[pw_idx].len_pwd);
  padded_password[array_password[idx].len_pwd] = 0x80; // padded_password[0..len_password-1] = password; padded_password[len_password] = 1000 0000
  memset(padded_password + array_password[idx].len_pwd + 1, 0, 56 - array_password[pw_idx].len_pwd - 1);
  len_password_bits = array_password[pw_idx].len_pwd * 8;
  memcpy(padded_password + 56, &len_password_bits, 8);


  //Per ogni parola, viene preso in considerazione l'unico chunk da 64 byte
  // Il chunk viene diviso in elementi da 32 bit (64 byte -> 16 elementi da 32 bit)
  M = (uint32_t *)(padded_password);
  // A, B, C, D assumono i valori iniziali delle variabili a0, b0, c0, d0
  A = a0, B = b0, C = c0, D = d0;

  // 4 round di 16 operazioni
  for (uint16_t i = 0; i < 64; i++) {
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
  if(strcmp(hash_calcolato, hash_da_craccare) == 0) printf("L'hash corrisponde alla passsword %s\n", array_password[pw_idx]);
  }
}

int main(int argc, char *argv[]) {
    //Controllo numero argomenti
    if(argc != 3){
        perror("ERRORE-Il numero di parametri passati in ingresso al programmaè diverso da 2\n");
        perror("Usage: [wordlist] [hash MD5]\n");
        exit(-1);
    }

    result_wordlist wordlist = read_wordlist(argv[1]);

    if(wordlist.error_code == -1){
        perror("ERRORE-La __m128i*) &array_hash[k].hashwordlist non esiste o non è un file .txt\n");
        perror("Usage: [wordlist] [hash MD5]\n");
    }else if(wordlist.error_code == -2){
        perror("ERRORE-La wordlist contiene delle password con una lunghezza maggiore di 56 caratteri\n");
        perror("Usage: [wordlist] [hash MD5]\n");
    }else{
        //DIMENSIONAMENTO GRIGLIA E BLOCCHI 
        dim3 blockSize(128);         //PRIMO TEST, SUCCESSIVAMENTE PROVARE 256 E 512
        int dimGrid = (wordlisit.num_password + blockSize.x - 1) / blockSize.x;
        dim3 gridSize(dimGrid);

    	CHECK(cudaMemcpyToSymbol(K, K_cpu, 64*sizeof(uint32_t)));
      CHECK(cudaMemcpyToSymbol(s, s_cpu, 64*sizeof(uint8_t)));
      CHECK(cudaMemcpyToSymbol(g, g_cpu, 64*sizeof(uint8_t)));
      CHECK(cudaMemcpyToSymbol(a0, a0_cpu, sizeof(uint32_t)));
      CHECK(cudaMemcpyToSymbol(b0, b0_cpu, sizeof(uint32_t)));
      CHECK(cudaMemcpyToSymbol(c0, c0_cpu, sizeof(uint32_t)));
      CHECK(cudaMemcpyToSymbol(d0, d0_cpu, sizeof(uint32_t)));

      /* MEMORIA GLOBALE */
      password *d_array_password;
      size_t password_size = wordlist.num_password * sizeof(password);
      uint8_t* d_hash_craccare;

      CHECK(cudaMalloc(&d_hash_craccare, sizeof(uint8_t)*16);)
      CHECK(cudaMalloc((void **)&d_array_password, password_size)); // Allocazione della memoria sulla GPU
      
      CHECK(cudaMemcpy(d_array_password, wordlist.array_password, password_size, cudaMemcpyHostToDevice));
      CHECK(cudaMemcpy(d_hash_craccare, argv[2], sizeof(uint8_t)*16, cudaMemcpyHostToDevice));

      /* MEMORIA PINNED */

      password *h_array_password; // Memoria pinned per l'host
      size_t password_size = wordlist.num_password * sizeof(password);
      
      cudaMallocHost((void **)&h_array_password, password_size); // Allocazione della memoria pinned
      // Copia della parola dalla memoria normale all'host pinned (memoria host)
      cudaMemcpy(h_array_password, wordlist.array_password, password_size, cudaMemcpyHostToDevice);

      /* MEMORIA UNIFIED VIRTUAL ADDRESSING*/

      // Non è necessario allocare memoria separata per UVA, viene usata la memoria virtuale
      password *array_password;
      size_t password_size = wordlist.num_password * sizeof(password);
      // I dati vengono trasferiti automaticamente tra host e device quando necessari
      cudaMallocManaged((void **)&array_password, password_size); // Allocazione di memoria unificata

      hashcracking <<<gridSize, blockSize>>> ();

      // Sincronizzazione della GPU
      CHECK(cudaDeviceSynchronize());

        
      //Deallocazione hash
      _mm_free(array_hash);
    }
	
    cudaFree(array_password);
    cudaFreeHost(h_array_password);	
    free(wordlist.array_password);

    return 0;
}
