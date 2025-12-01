# SQL Injection:

## Research:
A SQL injection attack occurs when a malicious query is inserted through input data from the client’s browser into the application. If an application is vulnerable to this type of attack, threat actors can access the database to modify data, bypass authentication, issue commands, and more.

From STRIDE’s perspective, SQL injection can enable multiple threat categories once successfully exploited.
To know more about this model, please check this out. [STRIDE model](https://en.wikipedia.org/wiki/STRIDE_model)

We started with this vulnerability because it is common and can be easily exploited.

---

## ⭐ Situation
- The environment setup that we use is podman, and OWASP ZAP.
- While looking at the SQL injection room, I noticed the input form did not enforce strong input validation (Input form by the way is a type of user interface that collects information from a user). Since input/login forms are common attack targets in real-world applications, I decided to test whether the userID field was vulnerable to SQL injection. This scenario  mirrors a typical penetration test where an attacker attempts to bypass authentication by manipulating query logic.

---

## 🎯 Task
- Identify whether the `userID` input field was vulnerable to SQL injection.
- Exploit the vulnerability to bypass authentication and extract data from the database.
- Validate findings using both manual testing and automated scanning tools (OWASP ZAP).
- Analyze the root cause in the source code to understand why the vulnerability exists.
- Document the impact of SQL injection in real-world applications and highlight secure coding practices.

---

## 🛠️ Action
1. **Exploration**
- Let's check first what are the things we can do in the vulnerable website.
- By providing random number in the input form. It will give you the result. Interesting!

![Providing inputs](https://github.com/jum4nj1m/DVWA-Lab-Journal/blob/master/DVWA-Lab-Journal/Low/SQL-Injection/Images/navigate.png)

- Entering random strings and numbers produced no result. Might be that the application accepts it but drops it since it's not part of the userID list.

- It appeared that the maximum number of users was 5.

---

2. **EXPLOIT**

- To test for vulnerability, I entered a single `'` in the input form. The resulting error confirmed that the application was passing input directly to the SQL database, and the database interpreted our input as part of the SQL query logic rather than as plain data.

![Error message received](https://github.com/jum4nj1m/DVWA-Lab-Journal/blob/master/DVWA-Lab-Journal/Low/SQL-Injection/Images/error.png)

- As you can see it the image above, it appears that the error came from MariaDB server. Since MariaDB was forked from MySQL, there's a high chance that the syntax for both are the same. We can use MySQL as reference if we'll check what syntax are available to us. Before that, let us use the most common command to perform sql injection which is " ' OR 1=1".

- As shown in the image above, the error originated from the MariaDB server. Because MariaDB was also developed by MySQL developers, I think their syntax must be highly compatible. We can use MySQL documentation as a reference for further exploitation. For now, however, we will simply test with the most common SQL injection payload: `' OR 1=1`.

![SQL Injection](https://github.com/jum4nj1m/DVWA-Lab-Journal/blob/master/DVWA-Lab-Journal/Low/SQL-Injection/Images/injection.png)

- It worked! I am now able to see the available users in the database and we have confirmed that this site is vulnerable to SQL injection.

---

3. **ANALYSIS**

- Why did it work? In SQL and many programming languages, `'` and `"` delimit strings. When we submit text in the input form, the application captures it and constructs a query. For example, a valid user ID of `1` might produce:

```sql
SELECT first_name, last_name FROM users WHERE user_id = '1';
```

- Normally, if no information is provided in the input form, the query returns no results. However, by injecting `' OR '1=1`, the application bypasses the `userID` check and sends the modified query to the database. A non‑empty string evaluates to `TRUE` in a boolean context, so the condition `'1=1'` always succeeds. As a result, the query logic is forced to return all rows, effectively bypassing authentication.

```sql
SELECT first_name, last_name FROM users WHERE user_id =  '' OR '1=1';
```
**Equivalent to:**
```sql
SELECT first_name, last_name FROM users WHERE TRUE;
```

---

## ✅ Result
- Successful login bypass and extraction of user records.
- In production, this vulnerability could lead to unauthorized access, data breaches, regulatory non-compliance (e.g., GDPR, HIPAA), and reputational damage.

---

## 🔍 Vulnerability Analysis
3. **CODE REVIEW**
- Since the source code is available, we reviewed it to understand how the query works. Upon checking, we confirmed that the input is captured as a value and concatenated into the `$query` variable. It is then used in the `mysqli_query` function.

![Source-code](https://github.com/jum4nj1m/DVWA-Lab-Journal/blob/master/DVWA-Lab-Journal/Low/SQL-Injection/Images/sql-sourcecode.png)

4. **DYNAMIC SCANNING**
- Let us check out if the vulnerability can be detected in when we use OWASP ZAP. I opened up the application and turned on the proxy so ZAP can intercept my traffic. After sending a traffic in the input form. The URL will appear in the "History" tab.

- We then right-clicked the link and selected **Attack -> Active Scan.**

![Web URL](https://github.com/jum4nj1m/DVWA-Lab-Journal/blob/master/DVWA-Lab-Journal/Low/SQL-Injection/Images/owasp-zap.png)

- After completing the scan, we went to "Alerts" to check the findings. Based on the results, ZAP found two High Alerts related to SQL injection and XSS. Focusing on SQL injection, ZAP detected it as vulnerable due to the SQL syntax error found during the active scan.

![OWASP ZAP result](https://github.com/jum4nj1m/DVWA-Lab-Journal/blob/master/DVWA-Lab-Journal/Low/SQL-Injection/Images/sql-result.png)

- The root cause behind this vulnerability is the unparameterized queries as the inputs are directly embed into the query string.

---

## 🛡️ Remediation
- SQL injection is best prevented through the use of parameterized queries. By binding values to parameters, the SQL database will know that the value is expected to be a string. With no parameterization, the database interprets the entire query as SQL logic.

- Enforce strict type checks (e.g., integers must be validated as numeric) and reject unexpected characters.  

**Insecure code**
```php
<?php

if( isset( $_REQUEST[ 'Submit' ] ) ) {
    // Get input
    $id = $_REQUEST[ 'id' ];

    // Check database
    $query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

    // Get results
    while( $row = mysqli_fetch_assoc( $result ) ) {
        // Get values
        $first = $row["first_name"];
        $last  = $row["last_name"];

        // Feedback for end user
        echo "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
    }

    mysqli_close($GLOBALS["___mysqli_ston"]);
}

?> 
```

**Secure code**
```php
<?php

if( isset( $_REQUEST[ 'Submit' ] ) ) {
    //Validate input
    if (!isset($_REQUEST['id']) || !ctype_digit($_REQUEST['id'])) {
    die('Invalid ID');
    }
    // Get input
    $id = (int) $_REQUEST[ 'id' ];

    // Prepare statement
    $query = $GLOBALS["___mysqli_ston"]->prepare("SELECT first_name, last_name FROM users WHERE user_id = ?");
    if ($query === false) {
        die("Prepare failed: " . $GLOBALS["___mysqli_ston"]->error);
    }

    // Bind parameter
    $query->bind_param("i", $id);

    // Execute
    if (!$query->execute()) {
        die("Execute failed: " . $query->error);
    }

    // Get results
    $result = $query->get_result();
    while($row = $result->fetch_assoc()) {
        echo $row["first_name"] . " " . $row["last_name"];
    }

   $query->close();
}

?> 
```
- The updated code ensures that the data entered in the input form is an integer, and it uses a placeholder to perform a parameterized SQL query. However, this php code is subject for verification and testing as this is a source code from DVWA.

---

## 📌 Recommendations
- Apply least‑privilege principles to database accounts and segregate read/write operations.  
- Deploy a Web Application Firewall (WAF) or Runtime Application Self‑Protection (RASP) to block common injection payloads.  
- Implement centralized logging and SIEM monitoring to detect suspicious query activity.  
- Train developers on secure coding practices and integrate security checks into CI/CD pipelines.  
- Regularly perform vulnerability scanning and penetration testing to validate defenses.  

- References:
[SQL Injection - OWASP](https://www.owasp.org/index.php/SQL_Injection)

[SQL Injection Cheatsheet](https://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet)

---

## 📖 Conclusion
- This room demonstrated how SQL injection can bypass authentication and expose sensitive data when unparameterized queries are used. By exploiting the vulnerability, we confirmed the risk, validated it with dynamic scanning tools, and identified the insecure coding practice. The remediation using parameterized queries ensures user input is treated as data, not SQL logic. 
- This highlights the importance of secure coding practices in preventing high‑impact vulnerabilities.


