# Fare andare gli script

1. nano ~/.bashrc
2. aggiungi alla fine export PATH=$PATH:/home/roberto/pvs-script/bin (ho estratto i file li)
3. per aggiornare il file : source ~/.bashrc

# Gli script
Lo script `pvs-addcomment` può essere utilizzato per aggiungere il commento necessario a tutti i file .c nella directory corrente. Lo script `pvs-run` può essere usato per eseguire PVS-Studio. Devi eseguirlo con gli stessi argomenti della riga di comando che usi per il comando `make` quando compili il programma. Il report viene generato in formato HTML (nella directory `htmlreport`). Se desideri modificare le opzioni utilizzate per eseguire PVS-Studio, puoi modificare lo script `pvs-run`. Lo script `pvs-clean` esegue una pulizia rimuovendo i file generati da PVS-Studio, inclusi i file di risultato. Viene chiamato automaticamente da `pvs-run` prima di eseguire PVS-Studio.
