/**
* OWASP Benchmark Project
*
* This file is part of the Open Web Application Security Project (OWASP)
* Benchmark Project For details, please see
* <a href="https://www.owasp.org/index.php/Benchmark">https://www.owasp.org/index.php/Benchmark</a>.
*
* The OWASP Benchmark is free software: you can redistribute it and/or modify it under the terms
* of the GNU General Public License as published by the Free Software Foundation, version 2.
*
* The OWASP Benchmark is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
* even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details
*
* @author Juan Gama <a href="https://www.aspectsecurity.com">Aspect Security</a>
* @created 2015
* 
* Reduced version
*/

package servlet;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.sql.DataSource;

public class DatabaseHelper {
	private static Statement stmt;
	private static Connection conn;
	public static org.springframework.jdbc.core.JdbcTemplate JDBCtemplate;
	public static final boolean hideSQLErrors = false; // If we want SQL Exceptions to be suppressed from being displayed to the user of the web app.

	static {
		
		initDataBase();
		System.out.println("Spring context init() ");
		@SuppressWarnings("resource")
		org.springframework.context.ApplicationContext ac =
				new  org.springframework.context.support.ClassPathXmlApplicationContext("/context.xml", DatabaseHelper.class);
		javax.sql.DataSource data = (javax.sql.DataSource) ac.getBean("dataSource");
		JDBCtemplate = new org.springframework.jdbc.core.JdbcTemplate(data);
		System.out.println("Spring context loaded!");
	}
	
	public static void initDataBase(){
		try {
			executeSQLCommand("DROP PROCEDURE IF EXISTS verifyUserPassword");
			executeSQLCommand("DROP PROCEDURE IF EXISTS verifyEmployeeSalary");
			executeSQLCommand("DROP TABLE IF EXISTS USERS");
			executeSQLCommand("DROP TABLE IF EXISTS EMPLOYEE");
			executeSQLCommand("DROP TABLE IF EXISTS CERTIFICATE");
			executeSQLCommand("DROP TABLE IF EXISTS SCORE");
			
			executeSQLCommand("CREATE TABLE USERS (userid int NOT NULL GENERATED BY DEFAULT AS IDENTITY, username varchar(50), password varchar(50),PRIMARY KEY (userid));");
			executeSQLCommand("CREATE TABLE SCORE (userid int NOT NULL GENERATED BY DEFAULT AS IDENTITY, nick varchar(50), score INTEGER,PRIMARY KEY (userid));");
			executeSQLCommand("CREATE PROCEDURE verifyUserPassword(IN username_ varchar(50), IN password_ varchar(50))"
					+ " READS SQL DATA"
					+ " DYNAMIC RESULT SETS 1"
					+ " BEGIN ATOMIC"
					+ " DECLARE resultSet SCROLL CURSOR WITH HOLD WITH RETURN FOR SELECT * FROM USERS WHERE USERNAME = username_ AND PASSWORD = password_;"
					+ " OPEN resultSet;"
					+"END;");

			executeSQLCommand("create table EMPLOYEE ("
					+ "	   id INT NOT NULL GENERATED BY DEFAULT AS IDENTITY,"
					+ "	   first_name VARCHAR(20) default NULL,"
					+ "   last_name  VARCHAR(20) default NULL,"
					+ " salary     INT  default NULL," + " PRIMARY KEY (id)"
					+ "	);");

			executeSQLCommand("create table CERTIFICATE ("
					+ "	   id INT NOT NULL GENERATED BY DEFAULT AS IDENTITY,"
					+ " certificate_name VARCHAR(30) default NULL,"
					+ " employee_id INT default NULL," + " PRIMARY KEY (id)"
					+ ");");
			
			executeSQLCommand("CREATE PROCEDURE verifyEmployeeSalary(IN user_ varchar(50))"
					+ " READS SQL DATA"
					+ " DYNAMIC RESULT SETS 1"
					+ " BEGIN ATOMIC"
					+ " DECLARE resultSet SCROLL CURSOR WITH RETURN FOR SELECT * FROM EMPLOYEE WHERE FIRST_NAME = user_;"
					+ " OPEN resultSet;"
					+"END;");
			conn.commit();
			initData();
			
			System.out.println("DataBase tables/procedures created.");
		} catch (Exception e1) {
			System.out.println("Problem with database table/procedure creations: " + e1.getMessage());
		}
	}

	
	public static java.sql.Statement getSqlStatement() {
		if (conn == null) {
			getSqlConnection();
		}

		if (stmt == null) {
			try {
				stmt = conn.createStatement();
			} catch (SQLException e) {
				System.out.println("Problem with database init.");
			}
		}

		return stmt;
	}
	
	public static void reset(){
		initData();
	}
	
	private static void initData() {
		try {
			executeSQLCommand("INSERT INTO USERS (username, password) VALUES('User01', 'P455w0rd')");
			executeSQLCommand("INSERT INTO USERS (username, password) VALUES('User02', 'B3nchM3rk')");
			executeSQLCommand("INSERT INTO USERS (username, password) VALUES('User03', 'a$c11')");
			executeSQLCommand("INSERT INTO USERS (username, password) VALUES('foo', 'bar')");
			
			executeSQLCommand("INSERT INTO SCORE (nick, score) VALUES('User03', 155)");
			executeSQLCommand("INSERT INTO SCORE (nick, score) VALUES('foo', 40)");
			
			executeSQLCommand("INSERT INTO EMPLOYEE (first_name, last_name, salary) VALUES('foo', 'bar', 100)");
			conn.commit();
		} catch (Exception e1) {
			System.out.println("Problem with database init/reset: " + e1.getMessage());
		}
	}
	
	public static java.sql.Connection getSqlConnection() {
		if (conn == null) {
			try {
				InitialContext ctx = new InitialContext();
				DataSource datasource = (DataSource)ctx.lookup("java:comp/env/jdbc/BenchmarkDB");
				conn = datasource.getConnection();
				conn.setAutoCommit(false);
			} catch (SQLException | NamingException e) {
				System.out.println("Problem with getSqlConnection.");
				e.printStackTrace();
			}
		}
		return conn;
	}

	public static void executeSQLCommand(String sql) throws Exception {
		if (stmt == null) {
			getSqlStatement();
		}
		stmt.executeUpdate(sql);
	}
	
}
