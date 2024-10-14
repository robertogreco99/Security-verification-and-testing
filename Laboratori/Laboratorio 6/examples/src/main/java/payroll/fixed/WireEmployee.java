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