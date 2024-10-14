package servlet.fixed;

import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

import org.owasp.encoder.Encode;

public class Hello extends HttpServlet {
		
	public void doGet(HttpServletRequest request, HttpServletResponse response)
	   throws ServletException, IOException {
	   String name = request.getParameter("name");
	   response.setContentType("text/html");
	   PrintWriter out = response.getWriter();
	   out.println("<h1>Hello "+Encode.forHtml(name)+"</h1>");
	}
	
}