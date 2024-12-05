#include "wordlist.h"
#include "MD5.h"

#define N 100

void print_hash(hash *array_hash, unsigned int num_password) {
    for(int i = 0; i < num_password; i++){
        for (int j = 0; j < 16; j++) {
            printf("%02x", (unsigned char) array_hash[i].hash[j]);  // Stampa ogni byte in formato esadecimale
        }
        printf("\n");
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
        perror("ERRORE-La wordlist non esiste o non è un file .txt\n");
        perror("Usage: [wordlist] [hash MD5]\n");
    }else if(wordlist.error_code == -2){
        perror("ERRORE-La wordlist contiene delle password con una lunghezza maggiore di 56 caratteri\n");
        perror("Usage: [wordlist] [hash MD5]\n");
    }else{
        hash *array_hash = (hash *) _mm_malloc (wordlist.num_password*sizeof(hash), 16);// 16 byte (128 bit) aligned
        if (!array_hash) perror("ERRORE: Allocazione fallita per array_hash");

        register_initialization();
        printf("\n\nVERSIONE VETTORIALE\n");
        uint64_t clock_vettoriale = 0;
        for(int i = 0; i < N; i++){
            clock_vettoriale += md5_vettoriale(wordlist.array_password, wordlist.num_password, array_hash);
        }
        printf("Elapsed clock medio %lu\n", clock_vettoriale/N);

        printf("VERSIONE SCALARE\n");
        uint64_t clock_scalare = 0;
        for(int i = 0; i < N; i++){
            clock_scalare += md5(wordlist.array_password, wordlist.num_password, array_hash);
        }
        printf("Elapsed clock medio %lu\n", clock_scalare/N);

        double speedup = ((double)clock_scalare/N)/ ((double) clock_vettoriale/N);
        printf("Lo speedup ottenuto e' pari a (versione ottimizzata): %.4f\n", speedup);

        if (wordlist.array_password) {
            _mm_free(array_hash);            
           array_hash = NULL;
        }
    }

    if (wordlist.array_password) {
        _mm_free(wordlist.array_password);
        wordlist.array_password = NULL;
    }

    return 0;
}