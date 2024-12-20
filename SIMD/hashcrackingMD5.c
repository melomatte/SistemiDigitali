#include "wordlist.h"
#include "MD5_scalare.h"
#include "MD5_vettoriale.h"

#define N 100

void print_hash(char *hash) {
    for (uint8_t i = 0; i < 16; i++) {
        printf("%02x", (unsigned char) hash[i]);  // Stampa ogni byte in formato esadecimale
    }
    printf("\n");
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
        hash *array_hash = (hash *) _mm_malloc (wordlist.num_password*sizeof(hash), 16);// 16 byte (128 bit) aligned
        if (!array_hash) perror("ERRORE: Allocazione fallita per array_hash");

        printf("\n********************************\nELAPSED CLOCK MEDIO (RIPETIZIONE %d VOLTE)\n********************************\n", N);

        printf("\nVERSIONE VETTORIALE\n");
        uint64_t clock_vettoriale = 0;
        for(int i = 0; i < N; i++){
            clock_vettoriale += md5_vettoriale(wordlist.array_password, wordlist.num_password, array_hash);
        }
        printf("Elapsed clock medio %lu\n", clock_vettoriale/N);
        //print_hash(array_hash[0].hash);

        printf("\nVERSIONE VETTORIALE V1 (disposizione memoria differente -> overhead registri)\n");
        uint64_t clock_vettoriale_v1 = 0;
        for(int i = 0; i < N; i++){
            clock_vettoriale_v1 += md5_vettoriale_v1(wordlist.array_password, wordlist.num_password, array_hash);
        }
        printf("Elapsed clock medio %lu\n", clock_vettoriale_v1/N);
        //print_hash(array_hash[0].hash);

        printf("\nVERSIONE VETTORIALE V2 (disposizione memoria differente -> set)\n");
        uint64_t clock_vettoriale_v2 = 0;
        for(int i = 0; i < N; i++){
            clock_vettoriale_v2 += md5_vettoriale_v2(wordlist.array_password, wordlist.num_password, array_hash);
        }
        printf("Elapsed clock medio %lu\n", clock_vettoriale_v2/N);
        //print_hash(array_hash[0].hash);

        printf("\nVERSIONE VETTORIALE V3 (disposizione memoria differente -> load)\n");
        uint64_t clock_vettoriale_v3 = 0;
        for(int i = 0; i < N; i++){
            clock_vettoriale_v3 += md5_vettoriale_v3(wordlist.array_password, wordlist.num_password, array_hash);
        }
        printf("Elapsed clock medio %lu\n", clock_vettoriale_v3/N);
        //print_hash(array_hash[0].hash);

        printf("\nVERSIONE SCALARE\n");
        uint64_t clock_scalare = 0;
        for(int i = 0; i < N; i++){
            clock_scalare += md5(wordlist.array_password, wordlist.num_password, array_hash);
        }
        printf("Elapsed clock medio %lu\n", clock_scalare/N);
        //print_hash(array_hash[0].hash);

        printf("\n********************************\nSPEEDUP\n********************************\n");

        double speedup = ((double)clock_scalare/N)/ ((double) clock_vettoriale/N);
        printf("\nLo speedup ottenuto e' pari a : %.4f\n", speedup);

        speedup = ((double)clock_scalare/N)/ ((double) clock_vettoriale_v1/N);
        printf("\nV1 -> Lo speedup ottenuto e' pari a : %.4f\n", speedup);

        speedup = ((double)clock_scalare/N)/ ((double) clock_vettoriale_v2/N);
        printf("\nV2 -> Lo speedup ottenuto e' pari a : %.4f\n", speedup);

        speedup = ((double)clock_scalare/N)/ ((double) clock_vettoriale_v3/N);
        printf("\nV3 -> Lo speedup ottenuto e' pari a : %.4f\n", speedup);
    
        //Deallocazione hash
        _mm_free(array_hash);
    }

    free(wordlist.array_password);

    return 0;
}
