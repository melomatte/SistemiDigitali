Versione SIMD:
- All'interno della cartella "Librerie" sono definite le librerie incluse all'interno di "hashcrackingMD5.c"
- "hashcrackingMD5.c" contiene il main

Per compilare utilizzare il comando:
gcc hashcrackingMD5.c Librerie/MD5_scalare.c Librerie/MD5_vettoriale.c Librerie/wordlist.c Librerie/utils.c -o hashcrackingMD5 -msse4.1
