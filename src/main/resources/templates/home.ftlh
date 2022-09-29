<!DOCTYPE html>
<html lang="en">
<head>
  <title>Sample SAML Application</title>
  <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
  <link rel="stylesheet" href="https://cdn.simplecss.org/simple.min.css">
</head>
<body>
<h1>Welcome</h1>
<p>You are successfully signed in as <span>${name}</span></p>
<p>Your email address is <span>${emailAddress}</span></p>
<h2>Your Attributes</h2>
<table>
  <tr>
    <th>Key</th>
    <th>Value</th>
  </tr>
  <#list userAttributes as key, value>
    <tr>
      <td>${key}</td>
      <td>${value[0]}</td>
    </tr>
  </#list>
</table>

<a href="/logout"><button>Log Out</button></a>
</body>
</html>