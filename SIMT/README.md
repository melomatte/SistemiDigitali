# Implementa le configurazioni alternative

- **Grid 1D e blocchi 1D**
- **Grid 2D e blocchi 2D**
- Ogni thread lavora su più password (con intervallo di lavoro calcolato)
- Configurazioni dinamiche

## Esegui i test con diversi dataset

- Piccoli dataset (es. 10k password)
- Dataset medi (es. 100k password)
- Dataset enormi (es. 1M+ password)

## Profilazione con Nsight

- Monitora il kernel execution time
- Verifica il memory throughput per identificare colli di bottiglia nella gestione della memoria
- Controlla il livello di utilizzo dei multiprocessori della GPU (SM occupancy)
- Osserva l'efficienza del warping: eventuali divergenze tra i thread possono rallentare l'esecuzione

## Analizza i risultati

- Quali configurazioni massimizzano l'occupazione della GPU
- Identifica pattern di accesso alla memoria sub-ottimali
- Misura il tempo totale di esecuzione rispetto al throughput

## Itera e ottimizza

- Affina il codice basandoti sui dati raccolti. Ad esempio, riduci il numero di thread per blocco se l'occupazione è bassa, o modifica il layout della memoria per minimizzare conflitti tra i thread.
