# Imparare ad usare spotbugs
Prima di tutto, configuriamo SpotBugs per trovare solo vulnerabilità legate alla sicurezza. In Eclipse, apri l'elemento *Preferenze* dal menu *Finestra* e seleziona *Java - SpotBugs*. Qui, configuriamo il plugin selezionando solo la casella di sicurezza. Poi, ci assicuriamo che FindSecBugs sia correttamente impostato nella scheda dei plugin. Come primo test dello strumento, importaìiamo il progetto Eclipse disponibile nell'archivio zip del materiale del laboratorio, nella cartella *examples* (usa *File - Apri Progetti dal File System* e seleziona la cartella *examples*). Una volta creato il progetto, l'utility Maven all'interno di Eclipse dovrebbe scaricare automaticamente le dipendenze del progetto e compilarlo. Quando la configurazione e la compilazione del progetto sono completate, eseguiamo SpotBugs sul progetto (clicchiamo con il tasto destro sul nome del progetto e selezionaiamo*SpotBugs - Trova Bug*) e verificiamo che SpotBugs riporti, come previsto, alcune possibili vulnerabilità. Possiamo visualizzare i dettagli dei problemi trovati (descrizione del problema e possibili modi per risolverlo) aprendo la vista SpotBugs o, nella vista Java, aprendo i file Java per i quali è mostrato un numero (che indica il numero di problemi trovati) a destra del nome del file e cliccando sui simboli del bug.

# Analisi Statica con SpotBugs: exampples

##  Analisi e correzione del progetto *examples*

Il progetto *examples* contiene semplici esempi di classi Java, alcune delle quali affette da vulnerabilità di sicurezza. Il package `com.okta.jettyembedded` è preso dal progetto GitHub [okta-spring-boot-jetty-example](https://github.com/oktadeveloper/okta-spring-boot-jetty-example).

Utilizziamo SpotBugs per analizzare il codice del progetto, cercando vulnerabilità di sicurezza, e creiamo un rapporto con i nostri risultati. Classifichiamo i problemi segnalati in:

- **TP (True Positive)**: problemi effettivamente rilevati come vulnerabilità di sicurezza.
- **FP (False Positive)**: segnalazioni errate, ovvero problemi che non rappresentano reali vulnerabilità.

Per ogni problema, forniamo una spiegazione. Nel caso di vulnerabilità XSS (Cross-Site Scripting), specifichiamo anche il tipo di XSS (riflessa, memorizzata, basata su DOM, ecc.).
## Debolezze rilevate

Package `com.okta.jettyembedded`, file *HikesTodoServlet.java*:  
- **Linea 35**: **TP**: la variabile `hike`, che proviene dalla richiesta del servlet, viene scritta nella risposta, permettendo così un attacco XSS riflesso (reflected XSS) se la risposta viene incorporata in un documento HTML. Questa vulnerabilità può essere risolta verificando o sanitizzando la variabile `hike` quando viene estratta dal parametro della richiesta.  
```java
else if (this.hikes.contains(hike)) {
            response.setStatus(400);
            //qua ho il bug
            response.getWriter().print("The hike '"+hike+"' already exists.");
        }
```
- **Linee 23, 39, 52**: **TP**: il servlet scrive il contenuto di `hikes` nella risposta. Questi contenuti possono provenire da input dell'utente, memorizzati nella variabile `hikes` (vedi linea 38) e non validati né sanitizzati. Per questo motivo, il servlet è vulnerabile a XSS memorizzato (stored XSS). Questa vulnerabilità può essere risolta verificando o sanitizzando la variabile `hike` quando viene estratta dal parametro della richiesta.  
**In sintesi**, lo strumento ha segnalato 5 avvisi. Tutti sono **TP** (2 di essi si riferiscono alla stessa vulnerabilità). Le vulnerabilità riscontrate sono tutte XSS: una è XSS riflesso, mentre le altre sono XSS stored.
```java
protected void doGet(HttpServletRequest request, HttpServletResponse response)
        throws IOException {
            //qua ho il bug
        response.getWriter().print(String.join("\n", this.hikes));
    }
```
```java
else {
            this.hikes.add(hike);
            //qua ho il bug 
            response.getWriter().print(String.join("\n", this.hikes));
        }
```
```java
else {
            this.hikes.remove(hike);
            //qua ho il bug
            response.getWriter().print(String.join("\n", this.hikes));
        }
```


-Package `it.polito.dsp.echo.v0`, file *TcpEchoServer0.java*:  
- **Linea 20**: **TP**: l'applicazione utilizza un socket TCP normale invece di un socket TLS.
```java
		ServerSocket ss = new ServerSocket(port);
```

Package `servlet`, file *Hello.java*:  
- **Linea 14**: **TP**: l'applicazione è vulnerabile a XSS riflesso poiché scrive la variabile `name`, che proviene dalla richiesta, nella risposta HTML senza sanitizzarla né verificarla.
```java
public void doGet(HttpServletRequest request, HttpServletResponse response)
	   throws ServletException, IOException {
	   String name = request.getParameter("name");
	   response.setContentType("text/html");
	   PrintWriter out = response.getWriter();
       //qua ho il bug
	   out.println("<h1>Hello "+name+"</h1>");
	}
```

Package `servlet`, file *Test2.java*:  
- **Linea 29**: **FP**: in questa posizione, le stringhe `user` e `pass` non possono contenere valori arbitrari ma solo valori sicuri (caratteri alfabetici).  
```java
public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		response.setContentType("text/html;charset=UTF-8");

		String user = request.getHeader("USER");
		String pass = request.getHeader("PASSWORD");
		user = java.net.URLDecoder.decode(user, "UTF-8");
		pass = java.net.URLDecoder.decode(pass, "UTF-8");
		String sql;
		if (user.equals("adm") && pass.matches("^[a-zA-Z0-9_]+$")) {
			sql = "SELECT * from USERS where USERNAME='"+ user +"' and PASSWORD='"+ pass +"'";	
			try {
				java.sql.Statement statement =  DatabaseHelper.getSqlStatement();
				//qua ho il bug 
                //...
}

```
- **Linea 37**: **TP**: in questa posizione, la stringa `user` può avere qualsiasi valore e proviene dalla richiesta.
```java
public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		response.setContentType("text/html;charset=UTF-8");

		String user = request.getHeader("USER");
		String pass = request.getHeader("PASSWORD");
		user = java.net.URLDecoder.decode(user, "UTF-8");
		pass = java.net.URLDecoder.decode(pass, "UTF-8");
		String sql;
		if (user.equals("adm") && pass.matches("^[a-zA-Z0-9_]+$")) {
			sql = "SELECT * from USERS where USERNAME='"+ user +"' and PASSWORD='"+ pass +"'";	
			try {
				java.sql.Statement statement =  DatabaseHelper.getSqlStatement();
				statement.executeQuery( sql );
				response.setStatus(200);
			} catch (java.sql.SQLException e) {
				response.setStatus(500);
				response.getWriter().println("Error processing request.");
			}
		} else {
			response.setStatus(400);
            //qua ho il bug
			response.getWriter().println("Bad request for user "+user);
		} // end if
	}  // end doPost	
}
```

Package `payroll`, file *EmployeeController.java*:  
- **Linee 27, 33, 41, 48**: **TP**: il problema segnalato dallo strumento è la possibile divulgazione di proprietà non previste. Se assumiamo che le proprietà `id`, `name` e `role` della classe `Employee` siano tutte destinate ad essere esposte ai client, tecnicamente questo potrebbe essere un falso positivo. Tuttavia, l'esposizione di una classe di persistenza è una cattiva pratica di programmazione che potrebbe causare vulnerabilità reali in futuro (ad esempio, se altri campi sensibili, che non dovrebbero essere esposti, vengono aggiunti in futuro alla classe `Employee`). Per questo motivo, è consigliabile affrontare il problema.  
Inoltre, alle stesse linee, esiste un altro problema che non viene esplicitamente segnalato dallo strumento: la possibilità di avere una vulnerabilità XSS memorizzata, resa possibile dal fatto che l'oggetto `Employee` ricevuto nel corpo delle operazioni `post` e `put` non viene validato.
```java
@GetMapping("/employees")
  List<Employee> all() {
    return repository.findAll();
  }
  
```
```java
  @PostMapping("/employees")
  Employee newEmployee(@RequestBody Employee newEmployee) {
    return repository.save(newEmployee);
  }

```
```java
    return repository.findById(id)
      .orElseThrow(() -> new EmployeeNotFoundException(id));
  }
```
```java
return repository.findById(id)
      .map(employee -> {
        employee.setName(newEmployee.getName());
        employee.setRole(newEmployee.getRole());
        return repository.save(employee);
      })
      .orElseGet(() -> {
        newEmployee.setId(id);
        return repository.save(newEmployee);
      });
  }

```


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
## Sistemare i problemi dell'esempio
Correggiamo le vulnerabilità trovate nel progetto con l'aiuto dei suggerimenti forniti da SpotBugs, quindi eseguiamo nuovamente lo strumento per osservare come sono cambiati i risultati dell'analisi. 

Nota che, per utilizzare l'OWASP Encoder, è necessario aggiungere la sua dipendenza al file pom.xml. Questo può essere fatto aggiungendo il seguente testo all'elemento delle dipendenze del pom.xml:

```xml
<!-- https://mvnrepository.com/artifact/org.owasp.encoder/encoder -->
<dependency>
    <groupId>org.owasp.encoder</groupId>
    <artifactId>encoder</artifactId>
    <version>1.2.3</version>
</dependency>
```


### File HikesTodoServlet.java
```java
// aggiungo : 
import org.owasp.encoder.Encode;


@WebServlet(name = "HikesTodoServlet", urlPatterns = {"hikes"}, loadOnStartup = 1)
public class HikesTodoServlet extends HttpServlet {

questo  
/*
        else {
            this.hikes.add(hike);
            response.getWriter().print(String.join("\n", this.hikes));
        }
    }
*/

diventa 

 else {
            this.hikes.add(Encode.forHtml(hike));
            response.getWriter().print(String.join("\n", this.hikes));
        }

```

Un'altra possibilità è : 
```java
protected void doPost(HttpServletRequest request, HttpServletResponse response)
        throws IOException {
        String hike = request.getParameter("hike");
        if (hike == null) {
            response.setStatus(400);
            response.getWriter().print("Param 'hike' cannot be null.");
        }
        else if (this.hikes.contains(hike)) {
            response.setStatus(400);
            response.getWriter().print("The hike '"+hike+"' already exists.");
        }
        else if (!hike.matches("[a-zA-Z]+")) {
        	response.setStatus(400);
            response.getWriter().print("invalid 'hike' parameter");
        }
        else {
            this.hikes.add(hike);
            response.getWriter().print(String.join("\n", this.hikes));
        }
    }

    protected void doDelete(HttpServletRequest request, HttpServletResponse response)
        throws IOException {
        String hike = request.getParameter("hike");
        if (hike == null) {
            response.setStatus(400);
            response.getWriter().print("Param 'hike' cannot be null.");
        }
        else {
            this.hikes.remove(hike);
            response.getWriter().print(String.join("\n", this.hikes));
        }
    }
```

La differenza tra i due blocchi di codice riguarda la gestione dell'input `hike` prima di aggiungerlo alla lista `this.hikes`. 

**Versione originale**:

```java
else {
    this.hikes.add(hike);
    response.getWriter().print(String.join("\n", this.hikes));
}
```

In questa versione, l'oggetto `hike` viene aggiunto direttamente alla lista `this.hikes` senza alcuna modifica o sanificazione. Questo significa che se `hike` contiene caratteri speciali o input malevoli, potrebbero causare problemi di sicurezza come Cross-Site Scripting (XSS) quando il contenuto viene stampato nel browser.

**Versione modificata**:

```java
else {
    this.hikes.add(Encode.forHtml(hike));
    response.getWriter().print(String.join("\n", this.hikes));
}
```

In questa versione, prima di aggiungere `hike` alla lista, viene applicata la funzione `Encode.forHtml(hike)`. Questo metodo generalmente serve a "sanificare" l'input, convertendo caratteri speciali in entità HTML. Ad esempio, il carattere `<` diventa `&lt;` e `>` diventa `&gt;`. Questo processo è fondamentale per prevenire attacchi di XSS, in quanto rende il contenuto sicuro per la visualizzazione nel browser.

**Riepilogo**:

- **Sicurezza**: La seconda versione è più sicura perché sanitizza l'input per evitare potenziali vulnerabilità.
- **Funzionalità**: Entrambe le versioni aggiungono `hike` alla lista e stampano il contenuto, ma la versione modificata garantisce che il contenuto stampato non possa essere interpretato come codice eseguibile nel contesto HTML.

In sintesi, la differenza principale è l'uso della sanificazione dell'input nella seconda versione, che contribuisce a proteggere l'applicazione da vulnerabilità di sicurezza.

### File TcpEchoServer0.java
```java
// Questo 
	ServerSocket ss = new ServerSocket(port);
//Diventa
		ServerSocket ss = SSLServerSocketFactory.getDefault().createServerSocket(port);

```
La differenza tra le due linee di codice riguarda la creazione di un socket server in Java, ma con una differenza significativa: l'uso della sicurezza SSL/TLS.

1. **Socket Server normale**:
   ```java
   ServerSocket ss = new ServerSocket(port);
   ```
   In questo caso, viene creato un socket server normale che ascolta su una porta specificata (variabile `port`). Questo socket non offre alcuna protezione o crittografia dei dati trasmessi. È utile per comunicazioni semplici e dirette, ma non sicure.

2. **Socket Server SSL**:
   ```java
   ServerSocket ss = SSLServerSocketFactory.getDefault().createServerSocket(port);
   ```
   Qui, viene utilizzato un `SSLServerSocketFactory` per creare un socket server SSL. Questo tipo di socket è progettato per gestire comunicazioni sicure utilizzando il protocollo SSL/TLS. Significa che i dati trasmessi tra il client e il server sono crittografati, offrendo protezione contro l'intercettazione e garantendo l'integrità e l'autenticità dei dati.
**In sintesi:***
- **`ServerSocket`**: Crea un socket server semplice e non sicuro.
- **`SSLServerSocketFactory.getDefault().createServerSocket`**: Crea un socket server sicuro che utilizza SSL/TLS per crittografare i dati trasmessi.

### File Hello.java
```java
Questo :
public class Hello extends HttpServlet {
		
	public void doGet(HttpServletRequest request, HttpServletResponse response)
	   throws ServletException, IOException {
	   String name = request.getParameter("name");
	   response.setContentType("text/html");
	   PrintWriter out = response.getWriter();
     //qui il bug
	   out.println("<h1>Hello "+name+"</h1>");
	}
}
Diventa : 
public void doGet(HttpServletRequest request, HttpServletResponse response)
	   throws ServletException, IOException {
	   String name = request.getParameter("name");
	   response.setContentType("text/html");
	   PrintWriter out = response.getWriter();
	   out.println("<h1>Hello "+Encode.forHtml(name)+"</h1>");
	}
```
La differenza tra i due frammenti di codice riguarda la sicurezza nella gestione dell'input proveniente dall'utente, in particolare per prevenire attacchi di **Cross-Site Scripting** (XSS).

#### 1. Codice originale:
```java
out.println("<h1>Hello "+name+"</h1>");
```
In questo caso, il valore della variabile `name` viene inserito direttamente nel contenuto HTML senza alcuna forma di validazione o codifica. Se un utente malintenzionato invia un valore di `name` che contiene codice JavaScript o HTML (ad esempio, `<script>alert('XSS')</script>`), questo codice verrà eseguito nel contesto della pagina, creando una vulnerabilità di XSS. Questo è pericoloso perché permette a un attaccante di eseguire codice arbitrario nel browser degli utenti.

#### 2. Codice modificato:
```java
out.println("<h1>Hello "+Encode.forHtml(name)+"</h1>");
```
In questa versione, viene utilizzato `Encode.forHtml(name)` per codificare il valore di `name` prima di inserirlo nel contenuto HTML. La funzione `forHtml` trasforma caratteri speciali in entità HTML (ad esempio, `<` diventa `&lt;` e `>` diventa `&gt;`). Ciò significa che se un utente malintenzionato cerca di inviare codice HTML o JavaScript, questo verrà visualizzato come testo normale invece di essere interpretato ed eseguito dal browser.

#### In sintesi:
- **Vulnerabilità nel primo esempio**: l'inserimento diretto di dati dell'utente senza alcuna codifica può portare a vulnerabilità XSS.
- **Sicurezza nel secondo esempio**: l'uso di `Encode.forHtml(name)` protegge l'applicazione da attacchi XSS, assicurando che i dati dell'utente siano trattati come testo normale, evitando l'esecuzione di codice potenzialmente pericoloso.



### File test2.java
```Java
Questo
	public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		response.setContentType("text/html;charset=UTF-8");

		String user = request.getHeader("USER");
		String pass = request.getHeader("PASSWORD");
		user = java.net.URLDecoder.decode(user, "UTF-8");
		pass = java.net.URLDecoder.decode(pass, "UTF-8");
		String sql;
		if (user.equals("adm") && pass.matches("^[a-zA-Z0-9_]+$")) {
			sql = "SELECT * from USERS where USERNAME='"+ user +"' and PASSWORD='"+ pass +"'";	
			try {
				java.sql.Statement statement =  DatabaseHelper.getSqlStatement();
				statement.executeQuery( sql );
				response.setStatus(200);
			} catch (java.sql.SQLException e) {
				response.setStatus(500);
				response.getWriter().println("Error processing request.");
			}
		} else {
			response.setStatus(400);
			response.getWriter().println("Bad request for user "+user);
		} // end if
	}  // end doPost	


Diventa 

public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		response.setContentType("text/html;charset=UTF-8");

		String user = request.getHeader("USER");
		String pass = request.getHeader("PASSWORD");
		user = java.net.URLDecoder.decode(user, "UTF-8");
		pass = java.net.URLDecoder.decode(pass, "UTF-8");
		String sql;
		if (user.equals("adm") && pass.matches("^[a-zA-Z0-9_]+$")) {
			sql = "SELECT * from USERS where USERNAME='"+ user +"' and PASSWORD='"+ pass +"'";	
			try {
				java.sql.Statement statement =  DatabaseHelper.getSqlStatement();
				statement.executeQuery( sql );
				response.setStatus(200);
			} catch (java.sql.SQLException e) {
				response.setStatus(500);
				response.getWriter().println("Error processing request.");
			}
		} else {
			response.setStatus(400);
			response.getWriter().println("Bad request");
		} // end if
	}  // end doPost	
```
La differenza tra i due frammenti di codice riguarda principalmente la gestione dell'output nel caso in cui la richiesta non sia valida. Analizziamo le due versioni:

#### Codice originale:
```java
response.setStatus(400);
response.getWriter().println("Bad request for user "+user);
```
In questo caso, se la richiesta non è valida, il messaggio di errore restituito include il nome dell'utente (`user`) che ha effettuato la richiesta. Questa pratica può rappresentare un rischio per la sicurezza, poiché potrebbe rivelare informazioni sensibili o dettagli sull'utente ai potenziali attaccanti. Un attaccante potrebbe utilizzare queste informazioni per determinare se un nome utente specifico esiste o meno nel sistema.

#### Codice modificato:
```java
response.setStatus(400);
response.getWriter().println("Bad request");
```
Qui, il messaggio di errore è più generico e non include il nome dell'utente. Questo approccio è più sicuro, poiché non fornisce informazioni utili agli attaccanti riguardo ai dettagli della richiesta o all'esistenza di utenti specifici nel sistema. In questo modo, si riduce il rischio di attacchi come il *username enumeration*, in cui un attaccante potrebbe cercare di indovinare nomi utente validi sulla base delle risposte del server.

#### In sintesi:
- **Primo esempio**: Ritorna un messaggio di errore specifico che include il nome dell'utente, potenzialmente esponendo informazioni sensibili.
- **Secondo esempio**: Utilizza un messaggio di errore generico, riducendo il rischio di esposizione di dettagli sugli utenti e migliorando la sicurezza dell'applicazione.

### File employee controller.java
```java
Questo 
package payroll;

import java.util.List;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
class EmployeeController {

  private final EmployeeRepository repository;

  EmployeeController(EmployeeRepository repository) {
    this.repository = repository;
  }


  // Aggregate root
  // tag::get-aggregate-root[]
  @GetMapping("/employees")
  List<Employee> all() {
    return repository.findAll();
  }
  // end::get-aggregate-root[]

  @PostMapping("/employees")
  Employee newEmployee(@RequestBody Employee newEmployee) {
    return repository.save(newEmployee);
  }

  // Single item
  
  @GetMapping("/employees/{id}")
  Employee one(@PathVariable Long id) {
    
    return repository.findById(id)
      .orElseThrow(() -> new EmployeeNotFoundException(id));
  }

  @PutMapping("/employees/{id}")
  Employee replaceEmployee(@RequestBody Employee newEmployee, @PathVariable Long id) {
    
    return repository.findById(id)
      .map(employee -> {
        employee.setName(newEmployee.getName());
        employee.setRole(newEmployee.getRole());
        return repository.save(employee);
      })
      .orElseGet(() -> {
        newEmployee.setId(id);
        return repository.save(newEmployee);
      });
  }

  @DeleteMapping("/employees/{id}")
  void deleteEmployee(@PathVariable Long id) {
    repository.deleteById(id);
  }
}

Diventa

package payroll.fixed;

import java.util.ArrayList;
import java.util.List;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
class EmployeeController {

  private final EmployeeRepository repository;

  EmployeeController(EmployeeRepository repository) {
    this.repository = repository;
  }


  // Aggregate root
  // tag::get-aggregate-root[]
  @GetMapping("/employees")
  List<WireEmployee> all() {
    List<WireEmployee> list = new ArrayList<WireEmployee>();
    repository.findAll().forEach(e -> list.add(new WireEmployee(e))); 
    return list;
  }

  // end::get-aggregate-root[]

  @PostMapping("/employees")
  WireEmployee newEmployee(@RequestBody WireEmployee newEmployee) {
	validateEmployee(newEmployee);
    return new WireEmployee(repository.save(newEmployee.makeEmployee()));
  }

  // Single item

  @GetMapping("/employees/{id}")
  WireEmployee one(@PathVariable Long id) {
    
    return new WireEmployee(repository.findById(id)
      .orElseThrow(() -> new EmployeeNotFoundException(id)));
  }

  @PutMapping("/employees/{id}")
  WireEmployee replaceEmployee(@RequestBody WireEmployee newEmployee, @PathVariable Long id) {
    validateEmployee(newEmployee);
    
    return new WireEmployee(repository.findById(id)
      .map(employee -> {
        employee.setName(newEmployee.getName());
        employee.setRole(newEmployee.getRole());
        return repository.save(employee);
      })
      .orElseGet(() -> {
        newEmployee.setId(id);
        return repository.save(newEmployee.makeEmployee());
      }));
  }

  @DeleteMapping("/employees/{id}")
  void deleteEmployee(@PathVariable Long id) {
    repository.deleteById(id);
  }
  
  private void validateEmployee(WireEmployee employee) {
	  if (!employee.getName().matches("[a-zA-Z]+")
		  || !employee.getRole().matches("[a-zA-Z]+")) {
      	throw new BadEmployeeException();
      }
  }
  
}
```

La differenza tra i due frammenti di codice riguarda principalmente l'implementazione della classe `EmployeeController`, in particolare l'introduzione di una classe `WireEmployee` e miglioramenti nella gestione della validazione. Vediamo le modifiche più rilevanti:

#### 1. Modifiche al pacchetto
- **Originale**: 
  ```java
  package payroll;
  ```
- **Modificato**:
  ```java
  package payroll.fixed;
  ```
  La modifica del nome del pacchetto indica che la nuova implementazione potrebbe essere un'alternativa o una versione migliorata rispetto all'originale.

#### 2. Uso di `WireEmployee`
- **Originale**: 
  ```java
  List<Employee> all() {
      return repository.findAll();
  }
  ```
- **Modificato**:
  ```java
  List<WireEmployee> all() {
      List<WireEmployee> list = new ArrayList<WireEmployee>();
      repository.findAll().forEach(e -> list.add(new WireEmployee(e))); 
      return list;
  }
  ```
  Qui, viene utilizzata una classe `WireEmployee` (presumibilmente una DTO o Data Transfer Object) invece della classe `Employee` originale. Questo approccio può facilitare la separazione tra il modello di dominio e le rappresentazioni utilizzate per la comunicazione con i client.

#### 3. Creazione e ritorno di `WireEmployee`
- **Originale**: 
  ```java
  Employee newEmployee(@RequestBody Employee newEmployee) {
      return repository.save(newEmployee);
  }
  ```
- **Modificato**:
  ```java
  WireEmployee newEmployee(@RequestBody WireEmployee newEmployee) {
      validateEmployee(newEmployee);
      return new WireEmployee(repository.save(newEmployee.makeEmployee()));
  }
  ```
  La nuova implementazione include una chiamata a `validateEmployee(newEmployee)` per controllare la validità dei dati dell'impiegato prima di salvarlo nel repository. Inoltre, il nuovo impiegato viene convertito in un oggetto `Employee` tramite `newEmployee.makeEmployee()`.

#### 4. Validazione degli input
- **Aggiunta di validazione**:
  ```java
  private void validateEmployee(WireEmployee employee) {
      if (!employee.getName().matches("[a-zA-Z]+")
          || !employee.getRole().matches("[a-zA-Z]+")) {
          throw new BadEmployeeException();
      }
  }
  ```
  La funzione `validateEmployee` verifica che il nome e il ruolo dell'impiegato contengano solo caratteri alfabetici. Se la validazione fallisce, viene lanciata un'eccezione `BadEmployeeException`. Questo rappresenta un miglioramento rispetto all'implementazione originale, in quanto ora i dati sono convalidati prima del salvataggio.

#### 5. Ritorno di `WireEmployee` per gli endpoint
- Negli endpoint `one` e `replaceEmployee`, i dati restituiti ora sono di tipo `WireEmployee`, consentendo una rappresentazione più controllata e potenzialmente semplificata delle informazioni che vengono scambiate.

#### In sintesi:
- **Introduzione di `WireEmployee`**: Permette una separazione più chiara tra il modello di dominio e la rappresentazione dei dati.
- **Validazione degli input**: Aggiunge una verifica dei dati prima di salvare nel repository, aumentando la robustezza dell'applicazione.
- **Cambio di pacchetto**: Suggerisce un potenziale miglioramento o una nuova versione del sistema di gestione delle informazioni sugli impiegati.

#### Classe wireEmployee

package payroll.fixed;

import java.util.Objects;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;

class WireEmployee {

  private Long id;
  private String name;
  private String role;

  WireEmployee() {}

  WireEmployee(Long id, String name, String role) {
	this.id = id;
    this.name = name;
    this.role = role;
  }

  public WireEmployee(Employee e) {
	this.id = e.getId();
	this.name = e.getName();
	this.role = e.getRole();
  }

  public Long getId() {
    return this.id;
  }

  public String getName() {
    return this.name;
  }

  public String getRole() {
    return this.role;
  }

  public void setId(Long id) {
    this.id = id;
  }

  public void setName(String name) {
    this.name = name;
  }

  public void setRole(String role) {
    this.role = role;
  }

  @Override
  public boolean equals(Object o) {

    if (this == o)
      return true;
    if (!(o instanceof WireEmployee))
      return false;
    WireEmployee employee = (WireEmployee) o;
    return Objects.equals(this.id, employee.id) && Objects.equals(this.name, employee.name)
        && Objects.equals(this.role, employee.role);
  }

  @Override
  public int hashCode() {
    return Objects.hash(this.id, this.name, this.role);
  }

  @Override
  public String toString() {
    return "WireEmployee{" + "id=" + this.id + ", name='" + this.name + '\'' + ", role='" + this.role + '\'' + '}';
  }

  public Employee makeEmployee() {
	Employee ret = new Employee(name,role);
	ret.setId(id);
	return ret;
  }
}

# Analisi e Risoluzione delle vulnerabilità nell'OWASP Java VulnerableApp

L'OWASP Java VulnerableApp è un'applicazione Java volutamente vulnerabile utilizzata per testare gli analizzatori di codice.
Analisi dell'applicazione con Spotbugs

Dopo aver analizzato l'applicazione con Spotbugs, ci si concentra sui problemi trovati nelle seguenti classi:

    org.sasanlabs.service.vulnerability.sqlInjection.rrorBasedSQLInjectionVulnerability
    org.sasanlabs.service.vulnerability.pathTraversal.PathTraversalVulnerability
    org.sasanlabs.service.vulnerability.cmdInjection.CommandInjection

## ErrorBasedSQLInjectionVulnerability.java
```java
 @AttackVector(
            vulnerabilityExposed = VulnerabilityType.ERROR_BASED_SQL_INJECTION,
            description = "ERROR_SQL_INJECTION_URL_PARAM_APPENDED_DIRECTLY_TO_QUERY",
            payload = "ERROR_BASED_SQL_INJECTION_PAYLOAD_LEVEL_1")
    @VulnerableAppRequestMapping(
            value = LevelConstants.LEVEL_1,
            htmlTemplate = "LEVEL_1/SQLInjection_Level1")
    public ResponseEntity<String> doesCarInformationExistsLevel1(
            @RequestParam Map<String, String> queryParams) {
        String id = queryParams.get(Constants.ID);
        BodyBuilder bodyBuilder = ResponseEntity.status(HttpStatus.OK);
        try {
            ResponseEntity<String> response =
                    applicationJdbcTemplate.query(
                      //qua ho il bug
                            "select * from cars where id=" + id,
                            (rs) -> {
                                if (rs.next()) {
                                    CarInformation carInformation = new CarInformation();
                                    carInformation.setId(rs.getInt(1));
                                    carInformation.setName(rs.getString(2));
                                    carInformation.setImagePath(rs.getString(3));
                                    try {
                                        return bodyBuilder.body(
                                                CAR_IS_PRESENT_RESPONSE.apply(
                                                        JSONSerializationUtils.serialize(
                                                                carInformation)));
                                    } catch (JsonProcessingException e) {
                                        LOGGER.error("Following error occurred", e);
                                        return bodyBuilder.body(
                                                GENERIC_EXCEPTION_RESPONSE_FUNCTION.apply(e));
                                    }
                                } else {
                                    return bodyBuilder.body(
                                            ErrorBasedSQLInjectionVulnerability
                                                    .CAR_IS_NOT_PRESENT_RESPONSE);
                                }
                            });
            return response;
        } catch (Exception ex) {
            LOGGER.error("Following error occurred", ex);
            return bodyBuilder.body(GENERIC_EXCEPTION_RESPONSE_FUNCTION.apply(ex));
        }
    }

  @AttackVector(
            vulnerabilityExposed = VulnerabilityType.ERROR_BASED_SQL_INJECTION,
            description =
                    "ERROR_SQL_INJECTION_URL_PARAM_WRAPPED_WITH_SINGLE_QUOTE_APPENDED_TO_QUERY",
            payload = "ERROR_BASED_SQL_INJECTION_PAYLOAD_LEVEL_2")
    @VulnerableAppRequestMapping(
            value = LevelConstants.LEVEL_2,
            htmlTemplate = "LEVEL_1/SQLInjection_Level1")
    public ResponseEntity<String> doesCarInformationExistsLevel2(
            @RequestParam Map<String, String> queryParams) {
        String id = queryParams.get(Constants.ID);
        BodyBuilder bodyBuilder = ResponseEntity.status(HttpStatus.OK);
        try {
            ResponseEntity<String> response =
                    applicationJdbcTemplate.query(
                      //qua ho il bug 
                            "select * from cars where id='" + id + "'",
                            (rs) -> {
                                if (rs.next()) {
                                    CarInformation carInformation = new CarInformation();
                                    carInformation.setId(rs.getInt(1));
                                    carInformation.setName(rs.getString(2));
                                    carInformation.setImagePath(rs.getString(3));
                                    try {
                                        return bodyBuilder.body(
                                                CAR_IS_PRESENT_RESPONSE.apply(
                                                        JSONSerializationUtils.serialize(
                                                                carInformation)));
                                    } catch (JsonProcessingException e) {
                                        LOGGER.error("Following error occurred", e);
                                        return bodyBuilder.body(
                                                GENERIC_EXCEPTION_RESPONSE_FUNCTION.apply(e));
                                    }
                                } else {
                                    return bodyBuilder.body(
                                            ErrorBasedSQLInjectionVulnerability
                                                    .CAR_IS_NOT_PRESENT_RESPONSE);
                                }
                            });
            return response;
        } catch (Exception ex) {
            LOGGER.error("Following error occurred", ex);
            return bodyBuilder.body(GENERIC_EXCEPTION_RESPONSE_FUNCTION.apply(ex));
        }
    }
```
### Errori e soluzione 
- ErrorBasedSQLInjectionVulnerability, linee 64 e 109: TP: la variabile 'id' proviene da una richiesta HTTP e non viene convalidata né sanificata prima di essere inserita nella query SQL. La vulnerabilità può essere risolta utilizzando una dichiarazione preparata con l'id come parametro oppure sanificando l'id prima di utilizzarlo.
Ecco la traduzione richiesta:

**ErrorBasedSQLInjectionVulnerability, linea 64 e 208:** FP: la variabile 'id' proviene da una richiesta HTTP ma viene sanificata prima di essere inserita nella stringa SQL.
Ecco i pezzi di codice cambiati, focalizzati sull'uso di `PreparedStatement` nelle funzioni:

#### Funzione `doesCarInformationExistsLevel1`
```java
ResponseEntity<String> response =
        applicationJdbcTemplate.query(
                (conn) -> conn.prepareStatement("select * from cars where id=?"),
                (prepareStatement) -> {
                    prepareStatement.setString(1, id);
                },
                ...
```

#### Funzione `doesCarInformationExistsLevel3`
```java
ResponseEntity<String> response =
        applicationJdbcTemplate.query(
                (conn) -> conn.prepareStatement("select * from cars where id=?"),
                (prepareStatement) -> {
                    prepareStatement.setString(1, id);
                },
                ...
```


#### Considerazioni
- In ogni funzione, ho modificato la query per utilizzare un `PreparedStatement` con un parametro (`?`) e ho impostato il valore corrispondente con `setString(1, id)`.
## PathTraversalVulnerability.java
```java
@AttackVector(
            vulnerabilityExposed = {VulnerabilityType.PATH_TRAVERSAL},
            description = "PATH_TRAVERSAL_URL_PARAM_DIRECTLY_INJECTED")
    @VulnerableAppRequestMapping(
            value = LevelConstants.LEVEL_1,
            htmlTemplate = "LEVEL_1/PathTraversal")
    public ResponseEntity<GenericVulnerabilityResponseBean<String>> getVulnerablePayloadLevel1(
            @RequestParam Map<String, String> queryParams) {
        String fileName = queryParams.get(URL_PARAM_KEY);
        return this.readFile(() -> fileName != null, fileName);
    }
  ```
  ### Errori e soluzione
**PathTraversalVulnerability**, riga 53: il parametro `filename` potrebbe provenire da una fonte non affidabile (una richiesta HTTP). La vulnerabilità può essere risolta controllando la stringa del nome del file e rifiutandola se include caratteri punto.
Ecco come correggere la vulnerabilità nel codice relativo al Path Traversal. Aggiungerò un controllo per rifiutare nomi di file che contengono caratteri punto (`.`).

#### Codice Originale
```java
@AttackVector(
        vulnerabilityExposed = {VulnerabilityType.PATH_TRAVERSAL},
        description = "PATH_TRAVERSAL_URL_PARAM_DIRECTLY_INJECTED")
@VulnerableAppRequestMapping(
        value = LevelConstants.LEVEL_1,
        htmlTemplate = "LEVEL_1/PathTraversal")
public ResponseEntity<GenericVulnerabilityResponseBean<String>> getVulnerablePayloadLevel1(
        @RequestParam Map<String, String> queryParams) {
    String fileName = queryParams.get(URL_PARAM_KEY);
    return this.readFile(() -> fileName != null, fileName);
}
```

#### Codice Corretto
```java
@AttackVector(
        vulnerabilityExposed = {VulnerabilityType.PATH_TRAVERSAL},
        description = "PATH_TRAVERSAL_URL_PARAM_DIRECTLY_INJECTED")
@VulnerableAppRequestMapping(
        value = LevelConstants.LEVEL_1,
        htmlTemplate = "LEVEL_1/PathTraversal")
public ResponseEntity<GenericVulnerabilityResponseBean<String>> getVulnerablePayloadLevel1(
        @RequestParam Map<String, String> queryParams) {
    String fileName = queryParams.get(URL_PARAM_KEY);
    
    // Controllo per rifiutare fileName se contiene caratteri punto
    if (fileName != null && fileName.contains(".")) {
        return ResponseEntity.badRequest()
                             .body(new GenericVulnerabilityResponseBean<>("Invalid file name"));
    }

    return this.readFile(() -> fileName != null, fileName);
}
```

#### Spiegazione della Correzione
- **Controllo del Nome del File**: Prima di leggere il file, controlliamo se `fileName` è nullo e se contiene caratteri punto (`.`). Se contiene un punto, restituiamo una risposta di errore.
- **Risposta di Errore**: Utilizziamo `ResponseEntity.badRequest()` per inviare una risposta negativa con un messaggio di errore.

Questa modifica dovrebbe aiutare a prevenire la vulnerabilità di Path Traversal.
## CommandInjection,java
```java
 StringBuilder getResponseFromPingCommand(String ipAddress, boolean isValid) throws IOException {
        boolean isWindows = System.getProperty("os.name").toLowerCase().startsWith("windows");
        StringBuilder stringBuilder = new StringBuilder();
        if (isValid) {
            Process process;
            if (!isWindows) {
                process =
                        new ProcessBuilder(new String[] {"sh", "-c", "ping -c 2 " + ipAddress})
                                .redirectErrorStream(true)
                                .start();
            } else {
                process =
                        new ProcessBuilder(new String[] {"cmd", "/c", "ping -n 2 " + ipAddress})
                                .redirectErrorStream(true)
                                .start();
            }
            try (BufferedReader bufferedReader =
                    new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                bufferedReader.lines().forEach(val -> stringBuilder.append(val).append("\n"));
            }
        }
        return stringBuilder;
    }
```
### Soluzione e comandi
**CommandInjection, riga 44 e 49:**
TP: il parametro `ipAddress` potrebbe provenire da una fonte non affidabile (una richiesta HTTP) e non è sanitizzato o controllato. La vulnerabilità può essere corretta verificando che si tratti di un indirizzo IP valido.
Ecco la versione corretta del metodo `getResponseFromPingCommand`, che include un controllo per garantire che `ipAddress` sia un indirizzo IP valido prima di eseguire il comando ping. Se l'indirizzo non è valido, il metodo restituirà una risposta appropriata:

```java
import java.net.InetAddress;

StringBuilder getResponseFromPingCommand(String ipAddress, boolean isValid) throws IOException {
    // Controllo che l'indirizzo IP sia valido
    if (!isValid || !isValidIpAddress(ipAddress)) {
        return new StringBuilder("Invalid IP address.");
    }

    boolean isWindows = System.getProperty("os.name").toLowerCase().startsWith("windows");
    StringBuilder stringBuilder = new StringBuilder();
    Process process;

    // Esecuzione del comando ping
    if (!isWindows) {
        process = new ProcessBuilder(new String[]{"sh", "-c", "ping -c 2 " + ipAddress})
                .redirectErrorStream(true)
                .start();
    } else {
        process = new ProcessBuilder(new String[]{"cmd", "/c", "ping -n 2 " + ipAddress})
                .redirectErrorStream(true)
                .start();
    }
    
    try (BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
        bufferedReader.lines().forEach(val -> stringBuilder.append(val).append("\n"));
    }
    return stringBuilder;
}

// Metodo per verificare se un indirizzo IP è valido
private boolean isValidIpAddress(String ipAddress) {
    try {
        InetAddress.getByName(ipAddress);
        return true;
    } catch (Exception e) {
        return false;
    }
}
```

#### Modifiche effettuate:
1. **Verifica dell'indirizzo IP:** È stato aggiunto un controllo per verificare se `ipAddress` è un indirizzo IP valido prima di eseguire il comando ping. Se l'indirizzo non è valido, il metodo restituisce un messaggio indicante che l'indirizzo è invalido.
2. **Metodo `isValidIpAddress`:** È stata creata una funzione ausiliaria `isValidIpAddress` che utilizza `InetAddress.getByName` per verificare la validità dell'indirizzo IP.

In questo modo, hai mitigato il rischio di eseguire comandi con input potenzialmente non sicuri.

# Analisi e Correzione della vulnerabilità CVE-2021-37573

CVE-2021-37573 è una vulnerabilità del Tiny Java Web Server e Servlet Container (TJWS, http://tjws.sourceforge.net/). Per vostra comodità, il report CVE è disponibile nel materiale del laboratorio. Dopo averlo esaminato, il vostro compito è trovare la vulnerabilità nel codice Java dell'applicazione, con l'aiuto di SpotBugs, e poi correggerla. Per vostra comodità, potete trovare una parte rilevante del codice (presa dalla versione 115, che è l'ultima colpita dalla vulnerabilità) nella cartella TJWS2, con un file pom.xml che automatizza il download delle sue dipendenze e la sua compilazione. Questo codice può essere importato in Eclipse come un Progetto Maven, come fatto per gli altri progetti.

```java
	private void dispatchPathname(HttpServletRequest req, HttpServletResponse res, boolean headOnly, String path)
			throws IOException {
		log("path trans: " + req.getPathTranslated());
		String filename = req.getPathTranslated() != null ? req.getPathTranslated().replace('/', File.separatorChar)
				: "";
		File file = new File(filename);
		log("retrieving '" + filename + "' for path " + path);
		if (file.exists()) {
			if (!file.isDirectory())
				serveFile(req, res, headOnly, path, file);
			else {
				log("showing dir " + file);
				if (redirectDirectory(req, res, path, file) == false)
					showIdexFile(req, res, headOnly, path, filename);
			}
		} else
			res.sendError(HttpServletResponse.SC_NOT_FOUND, file.getName()+" not found");
	}
```
### Errori e soluzione 
La vulnerabilità (un XSS riflesso) si trova nel file Acme.Serve.FileServlet.java alla riga 183: il nome del file che viene inserito nel corpo della risposta 404 proviene dal percorso nell'URL della richiesta. La vulnerabilità può essere corretta sanificando il nome del file o controllandolo prima di inserirlo nella risposta. Vedi Acme.Serve.FileServlet fixed.java.
Per risolvere la vulnerabilità di tipo XSS riflesso (Cross-Site Scripting) nel codice Java fornito, dobbiamo sanificare il nome del file prima di utilizzarlo nella risposta HTTP. Questo impedisce che un attaccante possa inserire codice dannoso attraverso il nome del file.

Ecco come puoi modificare il metodo `dispatchPathname` per risolvere la vulnerabilità:

#### Modifiche al Codice

1. **Sanificazione del Nome del File**: Utilizzare una funzione di sanificazione per rimuovere caratteri pericolosi o indesiderati dal nome del file.
2. **Validazione del Nome del File**: Controllare che il nome del file non contenga sequenze di caratteri che potrebbero portare a comportamenti indesiderati.

#### Codice Aggiornato

```java
private void dispatchPathname(HttpServletRequest req, HttpServletResponse res, boolean headOnly, String path)
        throws IOException {
    log("path trans: " + req.getPathTranslated());
    String filename = req.getPathTranslated() != null ? req.getPathTranslated().replace('/', File.separatorChar) : "";
    
    // Sanificare il nome del file per prevenire attacchi XSS
    filename = sanitizeFileName(filename);

    File file = new File(filename);
    log("retrieving '" + filename + "' for path " + path);
    if (file.exists()) {
        if (!file.isDirectory())
            serveFile(req, res, headOnly, path, file);
        else {
            log("showing dir " + file);
            if (!redirectDirectory(req, res, path, file))
                showIdexFile(req, res, headOnly, path, filename);
        }
    } else
        res.sendError(HttpServletResponse.SC_NOT_FOUND, file.getName() + " non trovato");
}

// Metodo per sanificare il nome del file
private String sanitizeFileName(String fileName) {
    // Rimuovere caratteri non alfanumerici e consentire solo caratteri sicuri
    return fileName.replaceAll("[^a-zA-Z0-9._-]", ""); // Solo lettere, numeri, punto, trattino e underscore
}
```

#### Spiegazione delle Modifiche

1. **Sanificazione del Nome del File**:
   - Ho aggiunto un metodo `sanitizeFileName` che utilizza un'espressione regolare per rimuovere qualsiasi carattere che non sia una lettera, un numero, un punto, un trattino o un underscore. Questo riduce significativamente il rischio di iniezioni di codice malevolo.

2. **Uso del Nome del File Sanificato**:
   - Il nome del file sanificato viene utilizzato nel resto del metodo `dispatchPathname`, assicurando che non venga mai utilizzato un input non controllato.

Questa modifica aiuta a proteggere l'applicazione da attacchi XSS e da altre vulnerabilità legate alla manipolazione dei nomi dei file. Assicurati di testare a fondo l'applicazione dopo aver apportato queste modifiche per garantire che funzioni come previsto e che le vulnerabilità siano state effettivamente mitigate.