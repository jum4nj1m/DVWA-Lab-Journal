# SQL Injection:

## Research:
SQL injection attack simply means that a SQL query can be inserted via the input data from the client's browser to the application. If an application is vulnerable to this type of attacks, threat actors can reach the database to modify changes, perform unauthorize authentication, issue commands, and a lot more.

In STRIDE's perspective, it can perform all security threats once successfully exploited.

We started with this vulnerability because it's a common issue and can be easily exploited.

## ⭐ Situation
Describe the context:
- The environment setup that we use is podman, burpsuite, and OWASP ZAP.
- While looking at the SQL injection room, I noticed the input form did not enforce strong input validation (Input form by the way is a type of user interface that collects information from a user). Since input/login forms are common attack targets in real-world applications, I decided to test whether the userID field was vulnerable to SQL injection. This scenario  mirrors a typical penetration test where an attacker attempts to bypass authentication by manipulating query logic.

---

## 🎯 Task
- bypass authentication, extract data, trigger XSS.
- Why this vulnerability is important to understand.

---

## 🛠️ Action
Step-by-step walkthrough:
1. Let's check first what are the things we can do in the vulnerable website.
- By providing random number in the input form. It will give you the result. Interesting!

![Providing inputs](./images/navigate.png)

- When random strings and numbers were provided, it will not show any result.

- Lastly, it appears that the maximum users are 5.

2. **EXPLOIT**

- To know if an application is vulnerable to SQL injection, put an "'" in the input form. If it resulted to an error, it means that the web application does not do input validation and the input can communicate to the database. 

![Error message received](./images/error.png)

- As you can see it the image above, it appears that the error came from MariaDB server. We can take a look at what syntax does MariaDB server use to see what queries we can do but before that, let us use the most common command to perform sql injection which is " ' OR 1=1".

![SQL Injection](./images/injection.png)

- It worked! I am now able to see the available users in the database and we have confirmed that this site is vulnerable to SQL injection.

3. **CODE REVIEW**

- Since the source code is available to us, we'll review it to understand how the query works. Upon checking, we have confirmed that the input will be captured as value and concatinated to the $query variable. It will then be used in the result variable to communicate to **mysqli_query**.

![Source-code](./images/sql_sourcecode.png)


4. **DYNAMIC SCANNING**
- Let us check out if the vulnerability can be detected in when we use OWASP ZAP. I opened up the application and turned on the proxy so ZAP can intercept my traffic. After sending a traffic in the input form. The URL will appear in the "History" tab.

- We can then right click the link and click "Attack" -> "Active Scan"

![Web URL](./images/owasp-zap.png)

- After we finish the scan, go to "Alerts" to check what alerts found by our tool. Based on the results, it found 2 H


4. **ANALYSIS**

- Why did it work? In many languages, ' and " are used to start and end a string. Once we submitted a text in the input form, the application will capture it and use it to call a command. In this case, if you provided a correct user ID of '1' as an example, it will be in this type of format and will pull the information from the database and show the result.

SELECT first_name, last_name FROM users WHERE user_id = 'F12321';

- Normally, if we did not put any information in the input form, nothing will happen. However, in this case, since we escaped using "' OR '1=1", it will bypass the userid and send it to the DB to query. In SQL, a non-empty string is treated as true in a boolean context (in MySQL/MariaDB). So this part always evaluates to true.

SELECT first_name, last_name FROM users WHERE user_id =  '' OR '1=1';

Equivalent to:

SELECT first_name, last_name FROM users WHERE TRUE;


## ✅ Result
Summarize the outcome:
- What you achieved (e.g., successful login bypass, data extraction).
- Evidence (screenshots, logs, request/response snippets).
- Impact if this vulnerability existed in a real-world app.

---

## 🔍 Vulnerability Analysis
- Root cause of the issue.
- How the application processes input incorrectly.
- Security principles violated.

---

## 🛡️ Remediation
- Recommended fixes (parameterized queries, input validation, secure session handling).
- Defensive coding practices.
- References (OWASP Cheat Sheets, PortSwigger guides).

---

## 🧠 Reflection
- What you learned from this lab.
- Challenges faced and how you overcame them.
- How this applies to real-world AppSec or bug bounty scenarios.