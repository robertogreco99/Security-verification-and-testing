package servlet;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet(value="/test2")
public class Test2 extends HttpServlet {
	
	private static final long serialVersionUID = 1L;
	
	@Override
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
}
