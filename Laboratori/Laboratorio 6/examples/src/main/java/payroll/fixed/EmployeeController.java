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