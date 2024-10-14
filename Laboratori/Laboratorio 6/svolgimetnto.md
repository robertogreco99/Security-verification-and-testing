# Imparare ad usare spotbugs
Prima di tutto, configuriamo SpotBugs per trovare solo vulnerabilità legate alla sicurezza. In Eclipse, apri l'elemento *Preferenze* dal menu *Finestra* e seleziona *Java - SpotBugs*. Qui, configuriamo il plugin selezionando solo la casella di sicurezza. Poi, ci assicuriamo che FindSecBugs sia correttamente impostato nella scheda dei plugin. Come primo test dello strumento, importaìiamo il progetto Eclipse disponibile nell'archivio zip del materiale del laboratorio, nella cartella *examples* (usa *File - Apri Progetti dal File System* e seleziona la cartella *examples*). Una volta creato il progetto, l'utility Maven all'interno di Eclipse dovrebbe scaricare automaticamente le dipendenze del progetto e compilarlo. Quando la configurazione e la compilazione del progetto sono completate, eseguiamo SpotBugs sul progetto (clicchiamo con il tasto destro sul nome del progetto e selezionaiamo*SpotBugs - Trova Bug*) e verificiamo che SpotBugs riporti, come previsto, alcune possibili vulnerabilità. Possiamo visualizzare i dettagli dei problemi trovati (descrizione del problema e possibili modi per risolverlo) aprendo la vista SpotBugs o, nella vista Java, aprendo i file Java per i quali è mostrato un numero (che indica il numero di problemi trovati) a destra del nome del file e cliccando sui simboli del bug.

## Analisi Statica con SpotBugs

##  Analisi e correzione del progetto *examples*

Il progetto *examples* contiene semplici esempi di classi Java, alcune delle quali affette da vulnerabilità di sicurezza. Il package `com.okta.jettyembedded` è preso dal progetto GitHub [okta-spring-boot-jetty-example](https://github.com/oktadeveloper/okta-spring-boot-jetty-example).

Utilizziamo SpotBugs per analizzare il codice del progetto, cercando vulnerabilità di sicurezza, e creiamo un rapporto con i nostri risultati. Classifichiamo i problemi segnalati in:

- **TP (True Positive)**: problemi effettivamente rilevati come vulnerabilità di sicurezza.
- **FP (False Positive)**: segnalazioni errate, ovvero problemi che non rappresentano reali vulnerabilità.

Per ogni problema, forniamo una spiegazione. Nel caso di vulnerabilità XSS (Cross-Site Scripting), specifichiamo anche il tipo di XSS (riflessa, memorizzata, basata su DOM, ecc.).

Package `com.okta.jettyembedded`, file *HikesTodoServlet.java*:  
- **Linea 35**: **TP**: la variabile `hike`, che proviene dalla richiesta del servlet, viene scritta nella risposta, permettendo così un attacco XSS riflesso (reflected XSS) se la risposta viene incorporata in un documento HTML. Questa vulnerabilità può essere risolta verificando o sanitizzando la variabile `hike` quando viene estratta dal parametro della richiesta.  
- **Linee 23, 39, 52**: **TP**: il servlet scrive il contenuto di `hikes` nella risposta. Questi contenuti possono provenire da input dell'utente, memorizzati nella variabile `hikes` (vedi linea 38) e non validati né sanitizzati. Per questo motivo, il servlet è vulnerabile a XSS memorizzato (stored XSS). Questa vulnerabilità può essere risolta verificando o sanitizzando la variabile `hike` quando viene estratta dal parametro della richiesta.  
**In sintesi**, lo strumento ha segnalato 5 avvisi. Tutti sono **TP** (2 di essi si riferiscono alla stessa vulnerabilità). Le vulnerabilità riscontrate sono tutte XSS: una è XSS riflesso, mentre le altre sono XSS stored.

Package `it.polito.dsp.echo.v0`, file *TcpEchoServer0.java*:  
- **Linea 20**: **TP**: l'applicazione utilizza un socket TCP normale invece di un socket TLS.

Package `servlet`, file *Hello.java*:  
- **Linea 14**: **TP**: l'applicazione è vulnerabile a XSS riflesso poiché scrive la variabile `name`, che proviene dalla richiesta, nella risposta HTML senza sanitizzarla né verificarla.

Package `servlet`, file *Test2.java*:  
- **Linea 29**: **FP**: in questa posizione, le stringhe `user` e `pass` non possono contenere valori arbitrari ma solo valori sicuri (caratteri alfabetici).  
- **Linea 37**: **TP**: in questa posizione, la stringa `user` può avere qualsiasi valore e proviene dalla richiesta.

Package `payroll`, file *EmployeeController.java*:  
- **Linee 27, 33, 41, 48**: **TP**: il problema segnalato dallo strumento è la possibile divulgazione di proprietà non previste. Se assumiamo che le proprietà `id`, `name` e `role` della classe `Employee` siano tutte destinate ad essere esposte ai client, tecnicamente questo potrebbe essere un falso positivo. Tuttavia, l'esposizione di una classe di persistenza è una cattiva pratica di programmazione che potrebbe causare vulnerabilità reali in futuro (ad esempio, se altri campi sensibili, che non dovrebbero essere esposti, vengono aggiunti in futuro alla classe `Employee`). Per questo motivo, è consigliabile affrontare il problema.  
Inoltre, alle stesse linee, esiste un altro problema che non viene esplicitamente segnalato dallo strumento: la possibilità di avere una vulnerabilità XSS memorizzata, resa possibile dal fatto che l'oggetto `Employee` ricevuto nel corpo delle operazioni `post` e `put` non viene validato.

## Persistence class
In Java, una ***persistence class*** è una classe che rappresenta un'entità che può essere salvata o recuperata da una base di dati, tipicamente utilizzata in contesti di persistenza come framework ORM (Object-Relational Mapping) come Hibernate o JPA (Java Persistence API). Queste classi mappano gli oggetti Java a tabelle del database, permettendo di eseguire operazioni di creazione, lettura, aggiornamento e cancellazione (CRUD) sui dati.

Una *persistence class* di solito include:

1. **Annotazioni di mapping**: Le annotazioni come `@Entity`, `@Table`, `@Id` vengono usate per specificare che la classe e i suoi campi corrispondono a una tabella e colonne in un database.
   
2. **Proprietà persistenti**: Sono i campi della classe che verranno mappati alle colonne del database.

3. **Metodi getter e setter**: Permettono di accedere e modificare i campi della classe.

Ecco un esempio di una *persistence class* in Java:

```java
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "employees")
public class Employee {
    
    @Id
    private Long id;
    private String name;
    private String role;

    // Costruttori, getter e setter
    public Employee() {}

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }
}
```

In questo esempio, la classe `Employee` è una *persistence class* che rappresenta un'entità `Employee` mappata alla tabella "employees" in un database. Il campo `id` è la chiave primaria della tabella.

Nel codice dell'esempio :
Nel codice che hai fornito, la classe EmployeeController non è una persistence class ma un controller che gestisce le richieste HTTP (come GET, POST, PUT, DELETE) per l'entità Employee. Tuttavia, la persistence class in questo contesto sarebbe la classe Employee, che non è presente nel codice fornito, ma che presumibilmente rappresenta l'entità persistente associata al database.

Il controller utilizza un repository, EmployeeRepository, per interagire con il database e salvare, aggiornare, eliminare o recuperare gli oggetti Employee. Questo suggerisce che esiste una classe Employee che funge da persistence class