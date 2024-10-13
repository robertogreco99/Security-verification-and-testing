# Appendice : distinguere le vulnerabilità :
Per distinguere tra i vari tipi di vulnerabilità o risultati generati da un analizzatore statico come **PVS-Studio**, si utilizzano termini specifici come **True Positive (TP)**, **False Positive (FP)**, **True Negative (TN)**, e **False Negative (FN)**. Questi termini sono usati per classificare la **precisione** e l'**accuratezza** dei risultati dell'analisi. Ecco come distinguerli:

### 1. **True Positive (TP)**:
   - **Definizione**: Un *True Positive* è un **problema reale** che è stato correttamente identificato dall'analizzatore come vulnerabilità o errore.
   - **Esempio**: Se l'analizzatore rileva un potenziale **buffer overflow** e, dopo la revisione, si conferma che il problema esiste davvero, questo è un **True Positive**.
   - **Interpretazione**: Il risultato è corretto e segnala un vero problema.

### 2. **False Positive (FP)**:
   - **Definizione**: Un *False Positive* è un **falso allarme**, cioè un errore o vulnerabilità segnalata dall'analizzatore, ma che, dopo una revisione, si scopre non essere un problema reale.
   - **Esempio**: L'analizzatore segnala un errore di uso di variabili non inizializzate, ma in realtà il codice è corretto e sicuro. In questo caso, si tratta di un **False Positive**.
   - **Interpretazione**: Il risultato è errato e segnala un problema inesistente.

### 3. **True Negative (TN)**:
   - **Definizione**: Un *True Negative* è quando l'analizzatore **non segnala alcun errore** e in effetti non ci sono problemi nel codice.
   - **Esempio**: L'analizzatore non segnala problemi in una sezione del codice correttamente scritta e, dopo revisione, si conferma che non ci sono vulnerabilità.
   - **Interpretazione**: Il risultato è corretto perché non ci sono errori o vulnerabilità.

### 4. **False Negative (FN)**:
   - **Definizione**: Un *False Negative* è quando l'analizzatore **non riesce a rilevare un problema** che in realtà esiste.
   - **Esempio**: Se c'è un buffer overflow nel codice, ma l'analizzatore non lo rileva, questo è un **False Negative**.
   - **Interpretazione**: Il risultato è errato perché l'analizzatore non ha segnalato un vero problema.

### Importanza dei TP, FP, FN, TN:
- **TP**: Vuoi avere **molti True Positives**, perché indicano che l'analizzatore è efficace nel rilevare problemi reali.
- **FP**: Troppi **False Positives** possono essere frustranti, poiché richiedono tempo per essere analizzati e spesso sono falsi allarmi.
- **FN**: Gli **False Negatives** sono pericolosi, perché significano che l'analizzatore ha mancato di rilevare vulnerabilità che possono compromettere la sicurezza.
- **TN**: **True Negatives** sono il risultato atteso quando il codice è privo di problemi, quindi non vengono segnalati falsi problemi.

### Esempio pratico:
Nel contesto del codice che hai fornito, la segnalazione di una vulnerabilità TP (True Positive) significa che l'analizzatore ha correttamente identificato un problema, come il **buffer overflow** nel codice, ed è un problema reale che va risolto. Se fosse un FP (False Positive), significherebbe che l'analizzatore ha segnalato un problema che in realtà non esiste.
# Come iniziare con flawfinder e PVS-Studio
Prima di iniziare con gli esercizi veri e propri, facciamo alcune prove per verificare che gli strumenti siano impostati correttamente.
## Esecuzione di flawfinder per riprodurre alcuni dei risultati mostrati in classe
Eseguiamo flawfinder sul file CWE121.c tratto dalla Juliet Test Suite del NIST per C/C++ e verifichiamo di ottenere 
i 3 risultati attesi che abbiamo visto in classe (si dovrebbero ottenere 3 risultati se si usa la versione 2.X, 4 risultati se si usano versioni precedenti).

Il codice : 
```c
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * Sinks: type_overrun_memcpy
 *    GoodSink: Perform the memcpy() and prevent overwriting part of the structure
 *    BadSink : Overwrite part of the structure by incorrectly using the sizeof(struct) in memcpy()
 * Flow Variant: 01 Baseline
 *
 * */

#include "std_testcase.h"

#ifndef _WIN32
#include <wchar.h>
#endif

/* SRC_STR is 32 char long, including the null terminator, for 64-bit architectures */
#define SRC_STR "0123456789abcdef0123456789abcde"

typedef struct _charVoid
{
    char charFirst[16];
    void * voidSecond;
    void * voidThird;
} charVoid;

#ifndef OMITBAD

void CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_01_bad()
{
    {
        charVoid structCharVoid;
        structCharVoid.voidSecond = (void *)SRC_STR;
        /* Print the initial block pointed to by structCharVoid.voidSecond */
        printLine((char *)structCharVoid.voidSecond);
        /* FLAW: Use the sizeof(structCharVoid) which will overwrite the pointer voidSecond */
        memcpy(structCharVoid.charFirst, SRC_STR, sizeof(structCharVoid));
        structCharVoid.charFirst[(sizeof(structCharVoid.charFirst)/sizeof(char))-1] = '\0'; /* null terminate the string */
        printLine((char *)structCharVoid.charFirst);
        printLine((char *)structCharVoid.voidSecond);
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

static void good1()
{
    {
        charVoid structCharVoid;
        structCharVoid.voidSecond = (void *)SRC_STR;
        /* Print the initial block pointed to by structCharVoid.voidSecond */
        printLine((char *)structCharVoid.voidSecond);
        /* FIX: Use sizeof(structCharVoid.charFirst) to avoid overwriting the pointer voidSecond */
        memcpy(structCharVoid.charFirst, SRC_STR, sizeof(structCharVoid.charFirst));
        structCharVoid.charFirst[(sizeof(structCharVoid.charFirst)/sizeof(char))-1] = '\0'; /* null terminate the string */
        printLine((char *)structCharVoid.charFirst);
        printLine((char *)structCharVoid.voidSecond);
    }
}

void CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_01_good()
{
    good1();
}

#endif /* OMITGOOD */

/* Below is the main(). It is only used when building this testcase on
   its own for testing or for building a binary to use in testing binary
   analysis tools. It is not used when compiling all the testcases as one
   application, which is how source code analysis tools are tested. */

#ifdef INCLUDEMAIN

int main(int argc, char * argv[])
{
    /* seed randomness */
    srand( (unsigned)time(NULL) );
#ifndef OMITGOOD
    printLine("Calling good()...");
    CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_01_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_01_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}


```

Eseguo con :
```bash
flawfinder CWE121.c
```
Risultato : 
```bash
Flawfinder version 2.0.19, (C) 2001-2019 David A. Wheeler.
Number of rules (primarily dangerous function names) in C/C++ ruleset: 222
Examining CWE121.c

FINAL RESULTS:

CWE121.c:99:  [3] (random) srand:
  This function is not sufficiently random for security-related functions
  such as key and nonce creation (CWE-327). Use a more secure technique for
  acquiring random values.
CWE121.c:41:  [2] (buffer) char:
  Statically-sized arrays can be improperly restricted, leading to potential
  overflows or other issues (CWE-119!/CWE-120). Perform bounds checking, use
  functions that limit length, or ensure that the size is larger than the
  maximum possible length.
CWE121.c:56:  [2] (buffer) memcpy:
  Does not check for buffer overflows when copying to destination (CWE-120).
  Make sure destination can always hold the source data.

ANALYSIS SUMMARY:

Hits = 3
Lines analyzed = 113 in approximately 0.00 seconds (30679 lines/second)
Physical Source Lines of Code (SLOC) = 60
Hits@level = [0]   0 [1]   0 [2]   2 [3]   1 [4]   0 [5]   0
Hits@level+ = [0+]   3 [1+]   3 [2+]   3 [3+]   1 [4+]   0 [5+]   0
Hits/KSLOC@level+ = [0+]  50 [1+]  50 [2+]  50 [3+] 16.6667 [4+]   0 [5+]   0
Minimum risk level = 1

Not every hit is necessarily a security vulnerability.
You can inhibit a report by adding a comment in this form:
// flawfinder: ignore
Make *sure* it's a false positive!
You can use the option --neverignore to show these.

```

## Esecuzione di pvs-studio su CVE121.c

```bash
pvs-addcomment
pvs-addcomment
```
Viene prodotto un report html con una sola entry

Risultato : 
![alt text](<Schermata del 2024-10-13 15-46-10.png>)

## Esecuzione di pvs-studio su test1.c
Ora, prova a eseguire PVS-Studio dal sito web di dimostrazione:
- https://pvs-studio.com/en/pvs-studio/godbolt/

Qui puoi modificare il codice C presente nell'area di testo a sinistra. Quando modifichi il codice, lo strumento si esegue automaticamente e puoi vedere i nuovi risultati a destra. Se preferisci, puoi aprire una visualizzazione alternativa, cliccando su "Modifica su Compiler Explorer". Prova a correggere il codice di esempio che viene visualizzato e verifica che gli errori segnalati scompaiano. L'archivio del laboratorio contiene un file di test molto semplice che presenta una classica vulnerabilità di formato stringa. Si trova nella directory test1. Copia il contenuto del file e incolla il codice nella finestra a sinistra, sovrascrivendo il codice precedente. La vulnerabilità di formato stringa dovrebbe essere evidenziata da PVS-Studio. Correggi il codice e controlla che PVS-Studio non segnali più l'errore dopo la correzione.


Il codice
```c
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
char buf[5012];
strncpy(buf, argv[1], sizeof buf - 1);
buf[sizeof buf - 1] = 0;
printf(buf); /* FIX */
return (0);
}


```

Per lanciarlo selezionare aggiungi tool : pvs-studio 
![alt text](<Schermata del 2024-10-13 15-58-13.png>)
Dopo la correzione : 
![alt text](<Schermata del 2024-10-13 15-59-13.png>)

## Esecuzione di test1.c con flawfinder

Otteniamo
```bash
test1.c:28:  [4] (format) printf:
  If format strings can be influenced by an attacker, they can be exploited
  (CWE-134). Use a constant for the format specification.
test1.c:23:  [2] (buffer) char:
  Statically-sized arrays can be improperly restricted, leading to potential
  overflows or other issues (CWE-119!/CWE-120). Perform bounds checking, use
  functions that limit length, or ensure that the size is larger than the
  maximum possible length.
test1.c:25:  [1] (buffer) strncpy:
  Easily used incorrectly; doesn't always \0-terminate or check for invalid
  pointers [MS-banned] (CWE-120).
```

Analizziamo i risultati ottenuti.

La prima vulnerabilità trovata da **flawfinder** . Ha un livello di gravità di [4], il che rende altamente probabile che non sia un falso positivo. Infatti, si riferisce a un possibile **attacco con stringhe di formato**, eseguito su `printf(buf)`. **PVS-Studio** ci ricorda che è più sicuro usare `printf("%s", buf)`.

La seconda vulnerabilità, con gravità [2], è solo un avviso di un possibile **buffer overflow**. Tuttavia, nel codice `test1.c` si può vedere che questo caso viene gestito utilizzando `strncpy(buf, argv[1], sizeof buf - 1)`. Questo è un **falso positivo**.

La terza vulnerabilità, con gravità [1], si riferisce a un possibile **buffer non terminato**. Tuttavia, nel codice sorgente, la terminazione viene aggiunta esplicitamente: `buf[sizeof buf - 1] = 0;`. Anche in questo caso, si tratta di un **falso positivo**.



# Analisi Statica con Flawfinder e PVS-Studio

## 3.1 Analisi di altri semplici esempi
Utilizza Flawfinder e PVS-Studio per analizzare gli altri semplici esempi presenti nel materiale di laboratorio (test2 e test3).  
Per ognuno di essi, esegui Flawfinder e PVS-Studio. Poi, analizza ciascun problema segnalato e decidi se si tratta di un vero positivo (TP) o di un falso positivo (FP). Scrivi un rapporto sui tuoi risultati contenente, per ciascun problema segnalato, la classificazione come TP o FP e una spiegazione per ciascuna decisione. Infine, ordina i TP in base alla loro gravità.

## Test2
Il codice : 
```c
#define RBUFLEN 128       // Definisce la lunghezza del buffer di ricezione a 128 caratteri
#define MAXSIZE 138       // Definisce la dimensione massima per i dati da manipolare a 138 caratteri

/* VARIABILI GLOBALI */
char buf[RBUFLEN];        // Buffer utilizzato per ricevere dati dal socket

/* Fornisce il servizio sul socket passato come parametro */
void service(int s)
{
    int n;  // Variabile per memorizzare il numero di byte letti

    for (;;)
    {
        n = read(s, buf, RBUFLEN-1);  // Legge dati dal socket 's' e li salva in 'buf'
        
        if (n < 0)  // Se si verifica un errore durante la lettura
        {
            printf("Read error\n");  // Stampa un messaggio di errore
            close(s);  // Chiude il socket
            printf("Socket %d closed\n", s);  // Conferma la chiusura del socket
            break;  // Esce dal ciclo infinito
        }
        else if (n == 0)  // Se la connessione viene chiusa dall'altra parte
        {
            printf("Connection closed by party on socket %d\n", s);  // Messaggio di chiusura connessione
            close(s);  // Chiude il socket
            break;  // Esce dal ciclo infinito
        }
        else  // Se sono stati letti dati correttamente
        {
            char local[MAXSIZE];  // Buffer per costruire il comando da eseguire
            char log[MAXSIZE];    // Buffer per salvare il comando da loggare

            buf[RBUFLEN-1] = '\0';  // Assicura che il buffer termini con '\0' per evitare overflow

            strcpy(local, "script.sh");  // Copia il comando "script.sh " in 'local'
            // Dopo questa operazione local contiene 11 byte: compreso il terminatore di stringa
            strcat(local, buf);  // Aggiunge i dati ricevuti al comando 'local'

            system(local);  // Esegue il comando di sistema

            strncpy(log, local, MAXSIZE);  // Copia il comando in 'log' per il log di sistema
            syslog(1, "%s", local);  // Registra il comando eseguito nei log di sistema

            strncpy(buf, log, MAXSIZE);  // Copia il log nel buffer di risposta

            if (write(s, buf, strlen(buf)) != strlen(buf))  // Scrive la risposta sul socket
                printf("Write error while replying\n");  // Messaggio di errore se la scrittura fallisce
            else
                printf("Reply sent\n");  // Messaggio di conferma della risposta inviata
        }
    }
}

```
### Flawfinder
Flawfinder trova 11 debolezze :
- test2.c:46:  [4] (buffer) strcat:
  Does not check for buffer overflows when concatenating to destination
  [MS-banned] (CWE-120). Consider using strcat_s, strncat, strlcat, or
  snprintf (warning: strncat is easily misused). ***Corrisponde a strcat(local,buf).FP (la destinazione local non può avere overflow perché inizialmente contiene una stringa di 10 byte correttamente terminata, mentre il buffer sorgente inizialmente contiene una stringa correttamente terminata che è al massimo di 127 byte; quindi, la stringa memorizzata nella variabile locale dopo la concatenazione è al massimo di 127+10=137 byte, che può essere memorizzata, incluso il suo terminatore di stringa, nei 138 byte allocati).***
- test2.c:47:  [4] (shell) system:
  This causes a new program to execute and is difficult to use safely
  (CWE-78). try using a library call that implements the same functionality
  if available. ***Corrisponde a system(local). severità elevata : meglio evitare la system ma usare un'altra funzione . E' un possibile TP .Lo è perchè parte di esso arriva da un buffer e quindi è inaffidabile.***
- test2.c:17:  [2] (buffer) char:
  Statically-sized arrays can be improperly restricted, leading to potential
  overflows or other issues (CWE-119!/CWE-120). Perform bounds checking, use
  functions that limit length, or ensure that the size is larger than the
  maximum possible length. Corrisponde a ***char buf[RBUFLEN]; TP, può andare in overflow dopo***
- test2.c:42:  [2] (buffer) char:
  Statically-sized arrays can be improperly restricted, leading to potential
  overflows or other issues (CWE-119!/CWE-120). Perform bounds checking, use
  functions that limit length, or ensure that the size is larger than the
  maximum possible length.***Corrisponde a  char local[MAXSIZE];Non può avere overflow. FP*** 
- test2.c:43:  [2] (buffer) char:
  Statically-sized arrays can be improperly restricted, leading to potential
  overflows or other issues (CWE-119!/CWE-120). Perform bounds checking, use
  functions that limit length, or ensure that the size is larger than the
  maximum possible length.***Corrisponde a  char log[MAXSIZE]; E' FP (il buffer viene scritto solo alla riga 48 e non può traboccare perché, sebbene il numero massimo di byte da copiare sia impostato su 140, che è maggiore della dimensione di destinazione, non verranno copiati più di 138 byte, poiché alla riga 48 la sorgente `local` contiene una stringa correttamente terminata che è al massimo lunga 138 byte, incluso il terminatore).***
- test2.c:48:  [1] (buffer) strncpy:
  Easily used incorrectly; doesn't always \0-terminate or check for invalid
  pointers [MS-banned] (CWE-120). ***Corrisponde  a strncpy(log,local,140); TP, trovato da pvs***
- test2.c:50:  [1] (buffer) strncpy:
  Easily used incorrectly; doesn't always \0-terminate or check for invalid
  pointers [MS-banned] (CWE-120). ***Corrisponde a strncpy(buf,log,MAXSIZE);TP, trovato da pvs***
- test2.c:45:  [2] (buffer) strcpy:
  Does not check for buffer overflows when copying to destination [MS-banned]
  (CWE-120). Consider using snprintf, strcpy_s, or strlcpy (warning: strncpy
  easily misused). Risk is low because the source is a constant string.
  ***Corrisponde a  45: strcpy(local,"script.sh ");. False positive, abbiamo detto che non può avere overflow***
- test2.c:26:  [1] (buffer) read:
  Check buffer boundaries if used in a loop including recursive loops
  (CWE-120, CWE-20).***Corrisponde a  n=read(s, buf, RBUFLEN-1);.Fp perchè la read è usata correttamente. Qui, read legge fino a RBUFLEN - 1 byte dal socket s. Questo lascia uno spazio nel buffer per il terminatore di stringa \0, prevenendo potenziali overflow.***
- riga 51 : **flawfinder, riga 51: TP** (buf è terminato con `0`, ma può traboccare, vedi la riga 50; quindi `strlen(buf)` potrebbe leggere al di fuori dei limiti di buf e causare un crash).
    - test2.c:51:  [1] (buffer) strlen:
  Does not handle strings that are not \0-terminated; if given one it may
  perform an over-read (it could cause a crash if unprotected) (CWE-126).
  Corrisponde a ***write(s, buf, strlen(buf))***
    - test2.c:51:  [1] (buffer) strlen:
  Does not handle strings that are not \0-terminated; if given one it may
  perform an over-read (it could cause a crash if unprotected) (CWE-126).
  Corrisponde  a ***strlen(buf)***

### pvs
test2.c:50:13: warning: ‘strncpy’ writing 140 bytes into a region of size 138 overflows the destination [-Wstringop-overflow=]
   50 |             strncpy(log,local,140);
      |             ^~~~~~~~~~~~~~~~~~~~~~
test2.c:45:18: note: destination object ‘log’ of size 138
   45 |             char log[MAXSIZE];
      |                  ^~~
test2.c:52:13: warning: ‘strncpy’ writing 138 bytes into a region of size 128 overflows the destination [-Wstringop-overflow=]
   52 |             strncpy(buf,log,MAXSIZE);
      |             ^~~~~~~~~~~~~~~~~~~~~~~~
test2.c:19:6: note: destination object ‘buf’ of size 128
   19 | char buf[RBUFLEN];               /* reception buffer */
      |      ^~~

![alt text](<Schermata del 2024-10-13 16-07-55.png>)
#### Commento :
***flawfinder** : trova
***pvs-studio*** trova due debolezze : di livello alto, entrambe dicono che una chiamata di una strncopy porta all'overflow di log e buf

1. buffer log :  
Log è grande MAXSIZE-->138.
Local è grande MAXSIZE-->138
strncpy(log,local,140) : strncpy(dest, src, numero caratteri da copiare)
DEVE ESSERE AL MASSIMO MAXSIZE-->138, non 140 
Soluzione : strncpy(log,local,MAXSIZE)

2. buffer buf
log è grande MAXSIZE -->138
bug è grande RBUFLEN -->128
strncpy(buf,log,MAXSIZE);
DEVE ESSERE AL MASSIMO RBUFLEN-->128, non 138 
Soluzione : strncpy(log,local,RBUFLEN)

***flawfinder e pvs linea 50 è un true positive** : // Vulnerabilità: il buffer 'log' può contenere una stringa lunga fino a 138 byte, inclusa la terminazione null ('\0'), 
mentre il buffer di destinazione 'buf' è lungo solo 128 byte. 
Poiché 'log' deriva parzialmente da 'buf', che contiene dati letti da un socket, 
esiste un rischio di overflow del buffer. La gravità di questa vulnerabilità è alta.

## Test3 
Il codice :
```c
#include "std_testcase.h"s
#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <direct.h>
#pragma comment(lib, "ws2_32") /* include ws2_32.lib when linking */
#define CLOSE_SOCKET closesocket
#else /* NOT _WIN32 */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define CLOSE_SOCKET close
#define SOCKET int
#endif

#define TCP_PORT 27015
#define IP_ADDRESS "127.0.0.1"
#define CHAR_ARRAY_SIZE (3 * sizeof(data) + 2)

void CWE122_Heap_Based_Buffer_Overflow__c_CWE129_connect_socket_02_bad()
{
    int data;
    /* Initialize data */
    data = -1;
#ifdef _WIN32
            WSADATA wsaData;
            int wsaDataInit = 0;
#endif
            int recvResult;
            struct sockaddr_in service;
            SOCKET connectSocket = INVALID_SOCKET;
            char inputBuffer[CHAR_ARRAY_SIZE];
            do
            {
#ifdef _WIN32
                if (WSAStartup(MAKEWORD(2,2), &wsaData) != NO_ERROR)
                {
                    break;
                }
                wsaDataInit = 1;
#endif
                /* POTENTIAL FLAW: Read data using a socket */
                connectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                if (connectSocket == INVALID_SOCKET)
                {
                    break;
                }
                memset(&service, 0, sizeof(service));
                service.sin_family = AF_INET;
                service.sin_addr.s_addr = inet_addr(IP_ADDRESS);
                service.sin_port = htons(TCP_PORT);
                if (connect(connectSocket, (struct sockaddr*)&service, sizeof(service)) == SOCKET_ERROR)
                {
                    break;
                }
                /* Abort on error or the connection was closed, make sure to leave
                space to append terminator */
                recvResult = recv(connectSocket, inputBuffer, CHAR_ARRAY_SIZE - 1, 0);
                if (recvResult == SOCKET_ERROR || recvResult == 0)
                {
                    break;
                }
                /* NUL-terminate the string */
                inputBuffer[recvResult] = '\0';
                /* Convert to int */
                data = atoi(inputBuffer);
            }
            while (0);
            if (connectSocket != INVALID_SOCKET)
            {
                CLOSE_SOCKET(connectSocket);
            }
#ifdef _WIN32
            if (wsaDataInit)
            {
                WSACleanup();
            }
#endif
        {
            int i;
            int * buffer = (int *)malloc(10 * sizeof(int));
            if (buffer == NULL) {exit(-1);}
            /* initialize buffer */
            for (i = 0; i < 10; i++)
            {
                buffer[i] = 0;
            }
            if (data >= 0)
            {
                buffer[data] = 1;
                /* Print the array values */
                for(i = 0; i < 10; i++)
                {
                    printIntLine(buffer[i]);
                }
            }
            else
            {
                printLine("ERROR: Array index is negative.");
            }
            free(buffer);
        }
}
```
### pvs
Non trova niente
### flawfinder
FINAL RESULTS:

test3.c:41:  [2] (buffer) char:
  Statically-sized arrays can be improperly restricted, leading to potential
  overflows or other issues (CWE-119!/CWE-120). Perform bounds checking, use
  functions that limit length, or ensure that the size is larger than the
  maximum possible length.***FP (il buffer di input non può avere overflow perché viene scritto solo alle righe 63 e 69 e in entrambi i casi i dati vengono scritti entro i limiti).** FP (il buffer di input non può traboccare perché viene scritto solo alle righe 63 e 69 e in entrambi i casi i dati vengono scritti entro i limiti).
test3.c:75:  [2] (integer) atoi:
  Unless checked, the resulting number can exceed the expected range
  (CWE-190). If source untrusted, check both minimum and maximum, even if the
  input had no minus sign (large numbers can roll over into negative number;
  consider saving to an unsigned value if that is intended): ***TP (la dimensione di inputbuffer è 3 * sizeof(data) + 2. Se assumiamo che int sia lungo 4 byte, la dimensione è 14. Con questa dimensione, è possibile rappresentare interi fino a 999999999999, il che potrebbe causare un overflow intero durante l'esecuzione di atoi. Poiché alla riga 95 data è utilizzato come indice in un'operazione di scrittura su buffer, la conseguenza è che un byte con valore 1 può essere scritto al di fuori dei limiti del buffer. Questo potrebbe essere sfruttato da un attaccante per scrivere il valore 1 in posizioni di memoria arbitrarie, causando potenzialmente un crash o un comportamento indesiderato.)***

## Nel complesso per test 2 e test3
TP, ordinato in ordine decrescente di gravità:  
**alto:** test2.c 47,17(50): l'attaccante può eseguire codice arbitrario sul bersaglio.  
**medio:** test3.c 71 (e 95): l'attaccante potrebbe causare un crash o un comportamento indesiderato.  
**basso:** test2.c 51: l'attaccante potrebbe causare un crash.

## Analysis and Fix of a real vulnerable code
Un'implementazione del comando file() di UNIX è stata colpita da una vulnerabilità di buffer overflow segnalata in un CVE. Questo esercizio consiste nell'analizzare il codice vulnerabile per trovare questa vulnerabilità. Nel materiale per il laboratorio, puoi trovare il pacchetto con i sorgenti della versione del software colpita dalla vulnerabilità. Esegui flawfinder sul file readelf.c, che contiene la vulnerabilità. Analizza i risultati restituiti da flawfinder e classificali in veri positivi (TP) e falsi positivi (FP). Per ciascuno di essi, spiega il motivo della tua classificazione.

Risultato : 
readelf.c:81:  [2] (buffer) char:
  Statically-sized arrays can be improperly restricted, leading to potential
  overflows or other issues (CWE-119!/CWE-120). Perform bounds checking, use
  functions that limit length, or ensure that the size is larger than the
  maximum possible length.
readelf.c:100:  [2] (buffer) char:
  Statically-sized arrays can be improperly restricted, leading to potential
  overflows or other issues (CWE-119!/CWE-120). Perform bounds checking, use
  functions that limit length, or ensure that the size is larger than the
  maximum possible length.
readelf.c:121:  [2] (buffer) char:
  Statically-sized arrays can be improperly restricted, leading to potential
  overflows or other issues (CWE-119!/CWE-120). Perform bounds checking, use
  functions that limit length, or ensure that the size is larger than the
  maximum possible length.
readelf.c:333:  [2] (buffer) char:
  Statically-sized arrays can be improperly restricted, leading to potential
  overflows or other issues (CWE-119!/CWE-120). Perform bounds checking, use
  functions that limit length, or ensure that the size is larger than the
  maximum possible length.
readelf.c:535:  [2] (buffer) memcpy:
  Does not check for buffer overflows when copying to destination (CWE-120).
  Make sure destination can always hold the source data.
readelf.c:720:  [2] (buffer) char:
  Statically-sized arrays can be improperly restricted, leading to potential
  overflows or other issues (CWE-119!/CWE-120). Perform bounds checking, use
  functions that limit length, or ensure that the size is larger than the
  maximum possible length.
readelf.c:723:  [2] (buffer) memcpy:
  Does not check for buffer overflows when copying to destination (CWE-120).
  Make sure destination can always hold the source data.
readelf.c:954:  [2] (buffer) memcpy:
  Does not check for buffer overflows when copying to destination (CWE-120).
  Make sure destination can always hold the source data.
readelf.c:996:  [2] (buffer) char:
  Statically-sized arrays can be improperly restricted, leading to potential
  overflows or other issues (CWE-119!/CWE-120). Perform bounds checking, use
  functions that limit length, or ensure that the size is larger than the
  maximum possible length.
readelf.c:1040:  [2] (buffer) memcpy:
  Does not check for buffer overflows when copying to destination (CWE-120).
  Make sure destination can always hold the source data.
readelf.c:1214:  [2] (buffer) char:
  Statically-sized arrays can be improperly restricted, leading to potential
  overflows or other issues (CWE-119!/CWE-120). Perform bounds checking, use
  functions that limit length, or ensure that the size is larger than the
  maximum possible length.
readelf.c:1327:  [2] (buffer) char:
  Statically-sized arrays can be improperly restricted, leading to potential
  overflows or other issues (CWE-119!/CWE-120). Perform bounds checking, use
  functions that limit length, or ensure that the size is larger than the
  maximum possible length.
readelf.c:1366:  [2] (buffer) memcpy:
  Does not check for buffer overflows when copying to destination (CWE-120).
  Make sure destination can always hold the source data.
readelf.c:1477:  [2] (buffer) char:
  Statically-sized arrays can be improperly restricted, leading to potential
  overflows or other issues (CWE-119!/CWE-120). Perform bounds checking, use
  functions that limit length, or ensure that the size is larger than the
  maximum possible length.
readelf.c:1478:  [2] (buffer) char:
  Statically-sized arrays can be improperly restricted, leading to potential
  overflows or other issues (CWE-119!/CWE-120). Perform bounds checking, use
  functions that limit length, or ensure that the size is larger than the
  maximum possible length.
readelf.c:1578:  [2] (buffer) char:
  Statically-sized arrays can be improperly restricted, leading to potential
  overflows or other issues (CWE-119!/CWE-120). Perform bounds checking, use
  functions that limit length, or ensure that the size is larger than the
  maximum possible length.
readelf.c:1331:  [1] (buffer) read:
  Check buffer boundaries if used in a loop including recursive loops
  (CWE-120, CWE-20).
readelf.c:1350:  [1] (buffer) strlen:
  Does not handle strings that are not \0-terminated; if given one it may
  perform an over-read (it could cause a crash if unprotected) (CWE-126).

### Analisi : 
lines 81,100,121,333: FP (l'array di dimensione statica è utilizzato in modo coerente nell'ambito della definizione)  
line 535: TP (il numero di byte copiati da memcpy, cioè la variabile descsz, non è controllato correttamente perché la condizione (descsz >= 4 || descsz <= 20) è sempre vera. Poiché il contenuto della sorgente così come di descsz proviene da un'operazione di lettura sul file, un attaccante potrebbe controllare ciò che viene scritto al di fuori del confine del buffer.)  
lines 559,626,656: FP (la destinazione può sempre contenere i dati sorgente perché il numero di byte copiati è la dimensione della destinazione)  
line 720: FP (l'array di dimensione statica è utilizzato in modo coerente nell'ambito della definizione)  
line 723: TP (questo è un potenziale overflow di buffer perché il numero di byte copiati da memcpy, cioè la variabile descsz, non è controllato nella funzione; a seconda di come viene chiamata la funzione, potrebbe essere una vulnerabilità o meno)  
line 954: FP (la destinazione può sempre contenere i dati sorgente)  
line 996: FP (l'array di dimensione statica è utilizzato in modo coerente nell'ambito della definizione)  
line 1040: FP (la destinazione può sempre contenere i dati sorgente)  
lines 1214,1327: FP (l'array di dimensione statica è utilizzato in modo coerente nell'ambito della definizione)  
lines 1340,1352,1366: FP (la destinazione può sempre contenere i dati sorgente)  
lines 1477,1478: FP (l'array di dimensione statica è utilizzato in modo coerente nell'ambito della definizione)  
line 1578: FP (l'array di dimensione statica non è utilizzato)  
line 1331: FP (read non può scrivere al di fuori del buffer)  
line 1350: TP (poiché nel codice non c'è evidenza che la stringa puntata da p sia terminata da null, questa potrebbe essere una vulnerabilità, ma è necessaria un'ulteriore analisi)  
In sintesi, abbiamo trovato 3 potenziali vulnerabilità. Quella segnalata nel CVE (che è CVE-2017-1000249) è la vulnerabilità alla linea 535.

### Analisi con pvs-studio
Ora, prova a utilizzare PVS-Studio per l'analisi del codice. Prima di poter compilare il codice con il comando `make`, è necessario generare il makefile, eseguendo i seguenti comandi (vedi README.DEVELOPER):

```bash
autoreconf -f -i
./configure --disable-silent-rules
```

Poi, puoi verificare che il codice possa essere compilato eseguendo:

```bash
make -j4
```

Un'altra operazione preliminare prima di eseguire PVS-Studio è inserire le due righe di commento speciali all'inizio di ciascun file C. Questo può essere fatto tramite lo script `pvs-addcomment`, dopo esserti spostato nella directory `src`:

```bash
cd src
pvs-addcomment
```

Infine, PVS-Studio può essere eseguito lanciando:

```bash
make clean
pvs-run -j4
```

Nota che ogni volta che vuoi ripetere l'analisi, devi pulire il progetto, perché PVS-Studio può analizzare solo i file che vengono effettivamente compilati (il comando `make` eviterà automaticamente la compilazione dei file se il risultato della compilazione è aggiornato). 

Guarda i problemi segnalati da PVS-Studio riguardo al file `readelf.c`. Cosa possiamo dire sulla capacità di PVS-Studio di trovare la vulnerabilità in questo file?

### Soluzione
PVS-Studio non ha segnalato la vulnerabilità alla linea 535 (quindi, tecnicamente, si tratta di un falso negativo per PVS-Studio). Tuttavia, PVS-Studio riporta la causa della vulnerabilità, cioè l'errore nell'espressione booleana della condizione che controlla l'operazione `memset` vulnerabile. Quindi, correggendo questo errore, anche la vulnerabilità viene risolta.

Trova una soluzione per la vulnerabilità e scrivi una versione corretta del file. Poi utilizza gli strumenti per analizzare nuovamente il codice.

La vulnerabilità può essere risolta correggendo la condizione errata in **`(descsz >= 4 && descsz <= 20)`**, che garantisce che **`descsz`** sia minore di 20, ovvero che vengano copiati meno di 20 byte. (Vedi **`readelf_fixed.c`** nella cartella delle soluzioni.)

#### Differenza tra i due file :
$ diff readelf.c readelf_fixed.c 
```bash
< 	    type == NT_GNU_BUILD_ID && (descsz >= 4 || descsz <= 20)) {
---
> 	    type == NT_GNU_BUILD_ID && (descsz >= 4 && descsz <= 20)) {

```


