# Parte 1 : file handshake1cie.pv
## Il file
Faccio girare proverif sul file `handshake1cie.pv`,che include la descrizione del protocollo e 3 query. L'assunzione è che l'attaccante conosca solo il canale pubblico c e le chiavi pubbliche
```bash
 (*
   Sample handshake protocol (typed version)
 *)
# tipo chiave per rappresentare una chiave crittografica (
type pkey.	(* public key *) # tipo per la chiave pubblica
type skey.	(* private key *) #tipo per la chiave privata
type keymat.	(* key material *) 
type result.	(* result of check signature *) #dove salvo il risultato del check della firma

free c:channel.			(* the public channel *) #canale di comunicazione pubblico
free s:bitstring [private]. 	(* the secret *) #il segreto

(* Public-key Encryption *) #crittografia a chiave pubblica
fun penc(bitstring, pkey): bitstring. # prende in ingresso il messaggio di tipo bistring e restituisce un messaggio crittograftato con la chiave pubblica pkey
fun pk(keymat): pkey. # genera una chiave pubblica a partire dal keymat
fun sk(keymat): skey. #genera una chiave privata a partire dal keymat
reduc forall x:bitstring, y:keymat; pdec(penc(x,pk(y)),sk(y)) = x.
# per ogni messaggio x di tipo bistring e per ogni materiale della chiave y di tipo keymat se si cifra x con la chiave publicata generata da y (pk(y)) e poi di decifra con la chiave privata generata da y (sk(y) si ottiene il messaggio originale

# in breve : chiave pubblicata usata per cifrare e privata per decriptare


(* Signatures *)
fun ok():result. #funzione restituisce ok come risultato della verifica
fun sign(bitstring, skey): bitstring. # prende in ingresso un messaggio e una chiave privata skey e resituisce una firma di tipo bistring
reduc forall m:bitstring, y:keymat; getmess(sign(m,sk(y))) = m.
# dato un messaggio firmato con la chiave privata (sk(y)) la funzione getmess restituisce il risultato originale
reduc forall m:bitstring, y:keymat; checksign(sign(m,sk(y)), pk(y)) = ok().
# la firma sign(m,sk(y)) può essere verificata usando la chiave pubblica pk(y) corrispondente. Se la firma è valida, la funzione checksign restituisce il messaggio ok

# in breve : chiave privata firma il messaggio, chiave pubblica verifica autenticità della firma. Solo chi possiede chiave privata può firmare il messaggio. Solo chi ha chiave pubblica può verificare validità della firma

(* Shared-key cryptography *)
fun senc(bitstring, bitstring): bitstring.
#prende un messaggio di tipo bistring e ???
reduc forall x: bitstring, y: bitstring; sdec(senc(x,y),y) = x.
#???

(* Test whether s is secret *)
query attacker(s).

(* Test reachability *)
event endA().
event endB().
query event(endA()).
query event(endB()).

(* Test authentication *)
event bA(pkey,pkey,bitstring).
event eB(pkey,pkey,bitstring).
query x:pkey,y:pkey,z:bitstring; inj-event(eB(x,y,z)) ==> inj-event(bA(x,y,z)).

(* The process *)

let pA(kpA: keymat, pkB: pkey) =
         new k:bitstring; # genera una chiave
	 event bA(pk(kpA),pkB,k); # parte evento ba
         out(c, penc(sign(k, sk(kpA)), pkB)); 
         # 1.firma la chiave  casuale con la propria chiave privata kpa 
         # 2.cifra con la chiave pubblica di b
         # 3.manda a b sul canale c
 	 in(c,x:bitstring); #9. riceve la rispsota di b
         let xs=sdec(x, k) in #10. decripta il messaggio x ricevuto con la chiave k
         event endA(); 0.  #11. termina

let pB(kpB: keymat, pkA: pkey) =
         in(c, y:bitstring);  # 4.riceve il messaggio di
         let y1=pdec(y, sk(kpB)) in # 5.decifra il messaggio ricevuto y con la propria chiave privata sk
         if checksign(y1, pkA)=ok() then #6.verifica se la firma di a è valida con la chiave pubblica di a
         let xk=getmess(y1) in #7.se è valida estrae la chiave casuale k (xk)
	 event eB(pkA,pk(kpB),xk); #evento pb
         out(c, senc(s, xk)); # 8.cifra il messaggio con la chiave xk e lo manda su c 
	 event endB(); 0.  # finisce evento

process 
         new kpA:keymat; new kpB:keymat;
         (!out(c, pk(kpA)); 0 | !out(c, pk(kpB)); 0 |
          !pA(kpA, pk(kpB))  | !pB(kpB, pk(kpA))
         )


(* EXPECTPV
Query not attacker(s[]) is true. # mi attendo che l'attaccante non riesca a ottenere il segreto
Query not event(endA) is false.
Query not event(endB) is false.
Query inj-event(eB(x_1,y_1,z)) ==> inj-event(bA(x_1,y_1,z)) is false.
END *)
```
## Query 
1. Secrecy di s
```bash
(* Test whether s is secret *)
query attacker(s).
## risultato atteso  :  
Query not attacker(s[]) is true. # mi attendo che l'attaccante non riesca a ottenere il segreto
```
2. Raggiungibilità della fine di ogni processo : si verifica che ogni processo possa raggiungere la fine
```bash
(* Test reachability *)
event endA().
event endB().
query event(endA()).
query event(endB()).
## risultato atteso --> raggiungono la fine
Query not event(endA) is false. 
Query not event(endB) is false.
```

3. Autenticazione da A a B :  se un processo B con chiave pubblica y riceve correttamente la chiave z, apparentemente proveniente da un processo A con chiave pubblica x, allora un processo A con chiave pubblica x ha realmente inviato la chiave z allo stesso processo e ogni operazione di ricezione corrisponde a un'operazione di invio distinta (iniettività).

```bash
(* Test authentication *)
event bA(pkey,pkey,bitstring).
event eB(pkey,pkey,bitstring).
query x:pkey,y:pkey,z:bitstring; inj-event(eB(x,y,z)) ==> inj-event(bA(x,y,z)).
##risultato atteso 
Query inj-event(eB(x_1,y_1,z)) ==> inj-event(bA(x_1,y_1,z)) is false.
#Questa query esprime una correspondence property tra due eventi, ovvero che se l'evento eB con parametri (x_1, y_1, z) avviene, allora dovrebbe avvenire anche l'evento bA con gli stessi parametri.
#L'uso di inj-event significa che si richiede che ogni occorrenza di eB corrisponda a un'unica occorrenza di bA, in una relazione di iniettività.
#Il risultato "false" implica che questa corrispondenza non è verificata correttamente: potrebbe accadere che eB avvenga senza che bA avvenga, oppure che ci sia una violazione dell'iniettività (ad esempio, più occorrenze di eB senza corrispondenti occorrenze di bA).
```
# Parte 2 : esecuzione dello script
Faccio girare `proverif handshake1cie.pv` e ottengo questo report : 
- Query "not attacker(s[])": Il risultato è true, il che significa che il messaggio segreto s[] non è vulnerabile agli attacchi e l'attaccante non può ottenere il valore di s[].
- Query "not event(endA)": Il risultato è false, indicando che l'evento endA è raggiungibile. In particolare, l'attaccante può ottenere il messaggio senc(s[], k_1) inviato in {24}, decodificarlo e quindi permettere l'esecuzione dell'evento endA.
- Query "not event(endB)": Anche questa query restituisce false, il che significa che l'evento endB è anch'esso raggiungibile. L'attaccante può ottenere il messaggio crittografato e completare la parte del protocollo legata a endB.
- Query "inj-event(eB(x_1,y_1,z)) ==> inj-event(bA(x_1,y_1,z))": Il risultato mostra che l'evento eB è condizionatamente associato all'evento bA, indicando che il protocollo non garantisce l'iniettività completa. Ovvero, esistono situazioni in cui un evento eB può avvenire senza che ci sia stato l'evento corrispondente bA, causando possibili ambiguità nella corrispondenza degli eventi.
Le proprietà 1 e 2 sono soddisfatte, la 3 no.

# Parte 3 : esecuzione dello script in modalità grafica
Faccio girare `proverif -graph . handshake1cie.pv`. Viene prodotta una rappresentazione grafica della attack trace trovata da proverif. Qual è il comportamento dell'attaccante nella traccia?

![alt text](<Schermata del 2024-10-07 16-45-03.png>)

Come si può vedere nella traccia d'attacco ricostruita da ProVerif (traceHandshake1cie3.pdf), l'attaccante rimanda il primo messaggio inviato da pA a un'altra istanza di pB.

Nel diagramma della traccia d'attacco  vediamo un'interazione tra processi onesti e l'attaccante. La traccia mostra vari passaggi che si verificano quando un attaccante cerca di riprodurre un messaggio inviato da un processo all'altro. La sezione di interesse è il comportamento evidenziato in questo modo:

1. **Processo pA** (Processo Onesto) invia un messaggio firmato da pk(kpA) al processo pB.
2. **Processo pB** riceve questo messaggio come parte della normale esecuzione.
3. L'**attaccante** interviene replicando un messaggio simile, sfruttando le informazioni già inviate da pA a un'altra istanza di pB. Questo comportamento è indicato da frecce che rappresentano il flusso del messaggio (puoi vedere l'attaccante che inietta il messaggio "event eB" nel punto in cui dovrebbe trovarsi una risposta legittima).
   
   La ripetizione del messaggio è chiaramente visibile nel fatto che l'attaccante utilizza lo stesso messaggio inviato prima da pA, ma lo ripete più avanti nella traccia.

In sintesi, il comportamento evidenziato è che l'attaccante sta sfruttando un replay del messaggio "event eB(pk(kpA), pk(kpB), k)" per ingannare il sistema, simulando una comunicazione valida. Puoi identificare questo comportamento dalle frecce parallele che attraversano i processi pA e pB, collegate al messaggio "event eB" generato due volte.

# Parte 4 : corregere lo script1.2 Correzione del protocollo  
Se desideriamo l'iniettività, dobbiamo correggere il protocollo. Un modo per farlo è aggiungere una fase preliminare, in cui pB invia per primo un valore generato casualmente (un nonce, che funge da ID di sessione) a pA per richiedere la chiave, e pA risponde a questa richiesta inviando lo stesso nonce insieme alla chiave. In questo modo, l'attaccante non dovrebbe essere in grado di ripetere il messaggio con la chiave in una sessione diversa. Scrivi uno script Proverif che descriva la versione corretta del protocollo (puoi partire dalla versione in handshake1cie.pv e modificarla). Nota che gli eventi della corrispondenza devono essere cambiati di conseguenza, includendo anche il nonce, altrimenti non è possibile distinguere gli eventi appartenenti a sessioni diverse.  
Dopo aver descritto la versione corretta, verifica che essa soddisfi la versione iniettiva della proprietà di autenticazione (e che tutti i processi arrivino alla fine). In caso di problemi, puoi usare il simulatore per capire il motivo.  
Riporta lo script Proverif con la versione corretta del protocollo: