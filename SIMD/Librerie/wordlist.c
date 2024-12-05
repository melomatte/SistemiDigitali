#include "wordlist.h"

int count_lines(FILE *f1) {
    int lines = 0;
    char c;
    int last_line = 0;

    while ((c = fgetc(f1)) != EOF) {
        if (c == '\n') {
            lines++;
            last_line = 0;
        } else last_line = 1;
    }

    // Se l'ultima riga non è terminata con \n, lines++
    if (last_line) lines++;

    return lines;
}

result_wordlist read_wordlist(char *fileName){
    FILE* wordlist;
    result_wordlist result;
    result.error_code = 0;
    char c, pwd[56];
    int i;
    int num_riga = 0;

    //Controllo esistenza file
    if((wordlist = fopen(fileName, "r")) == NULL) result.error_code = -1;
    else{
        //La wordlist presenta una struttura dove ogni riga contiene una password <= 56 caratteri
        //Il numero di password presenti all'interno della wordlist è pari al numero di righe del file
        result.num_password = count_lines(wordlist);
        //Lettura del file
        result.array_password = (password *) _mm_malloc (result.num_password*sizeof(password), 16);// 16 byte (128 bit) aligned
        if (!result.array_password) perror("ERRORE: Allocazione fallita per array_password");
        
        rewind(wordlist);

        while(num_riga < result.num_password){
            i = 0;
            //Leggo un carattere per ogni riga fino a \n o EOF (caso ultima riga)
            while((c = fgetc(wordlist)) != '\n' && c != EOF){
                if(i < 55){
                    pwd[i] = c;
                    i++;
                }else{ //Password di lunghezza maggiore della lunghezza consentita
                    result.error_code = -2;
                    break;
                }
            }

            if(result.error_code != -2){
                pwd[i] = '\0';
                strcpy(result.array_password[num_riga].pwd,pwd);
                result.array_password[num_riga].len_pwd = i;
                num_riga++;
            }else break;
        }
    }
    fclose(wordlist);
    return result;
}