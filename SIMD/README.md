# MD5 Password Cracker

## Input richiesto
Il programma richiede due argomenti da linea di comando:
1. **Wordlist**: un file di testo contenente le password da processare.
2. **Hash MD5**: un valore MD5 di riferimento.

**Esempio di utilizzo:**
```bash
//compilazione
gcc hashcrackingMD5.c Librerie/MD5_scalare.c Librerie/MD5_vettoriale.c Librerie/wordlist.c Librerie/utils.c -o hashcrackingMD5 -msse4.1
//esecuzione
./hashcrackingMD5 wordlist.txt 5d41402abc4b2a76b9719d911017c592

```

## Funzioni principali

### `print_hash`
Stampa un hash MD5 in formato esadecimale.
```c
void print_hash(char *hash) {
    for (uint8_t i = 0; i < 16; i++) {
        printf("%02x", (unsigned char) hash[i]);
    }
    printf("\n");
}
```

### `read_wordlist`
Carica la wordlist specificata come argomento e restituisce un oggetto contenente:
- **`array_password`**: un array di stringhe con le password della wordlist.
- **`num_password`**: il numero di password nella wordlist.
- **`error_code`**: un codice di errore per indicare problemi di caricamento:
  - `-1`: file inesistente o non valido.
  - `-2`: password più lunghe di 56 caratteri.

### `md5`
Implementazione scalare dell'algoritmo MD5 per calcolare l'hash di ogni password singolarmente.
- **Input:** array di password, numero di password, array per memorizzare gli hash.
- **Output:** hash MD5 per ciascuna password.

### `md5_vettoriale`
Versione parallela dell'algoritmo MD5, basata su SIMD, per elaborare più password contemporaneamente.
- **Input:** array di password, numero di password, array per memorizzare gli hash.
- **Output:** hash MD5 per ciascuna password calcolati in parallelo.

### `md5_vettoriale_extra`
Versione ottimizzata del metodo vettoriale per migliorare ulteriormente l'efficienza, riducendo l'overhead e sfruttando istruzioni SIMD avanzate.
- **Input:** array di password, numero di password, array per memorizzare gli hash.
- **Output:** hash MD5 per ciascuna password.

### `main`
La funzione principale esegue:
1. Validazione degli argomenti.
2. Lettura e validazione della wordlist tramite `read_wordlist`.
3. Allocazione della memoria per gli hash.
4. Calcolo degli hash con:
   - `md5` (scalare)
   - `md5_vettoriale`
   - `md5_vettoriale_extra`
5. Misurazione delle prestazioni e calcolo dello speedup.
6. Pulizia della memoria.

## Flusso di esecuzione
1. **Controllo degli argomenti:** verifica che i due argomenti richiesti siano stati forniti.
2. **Lettura della wordlist:** carica e valida il file della wordlist tramite `read_wordlist`.
3. **Allocazione della memoria:** alloca un array per memorizzare gli hash.
4. **Calcolo degli hash:** esegue ciascuna versione dell'algoritmo MD5 (scalare, vettoriale, vettoriale extra) per N iterazioni.
5. **Calcolo dello speedup:** confronta i tempi medi delle versioni scalari e vettoriali.
6. **Pulizia della memoria:** libera la memoria allocata per la wordlist e gli hash.
