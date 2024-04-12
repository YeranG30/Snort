# Snort Intrusion Detection System

## Project Overview
Utilizing Snort, this project involves creating and implementing tailored detection rules designed to identify and generate alerts for a variety of security threats. These include SQL Injections, Credit Card Data Leaks (Data Loss Prevention), and more, ensuring comprehensive coverage against potential vulnerabilities.

## Introduction
The purpose of this project is to demonstrate how Snort, an open-source network security tool, can be effectively used to enhance network security by detecting a range of sophisticated cyber threats in a controlled testing environment.

## Installing and Configuring Snort 
- Verified system meets the necessary specifications.
- Downloaded the latest version of Snort from the official website.
- Installed Snort using the default settings.
- Configured the snort.conf file for your network environment.
- Tested the installation to ensure that Snort is capturing and analyzing traffic correctly with   ```Snort -i 6 -c c:\snort\etc\snort.conf -T ```

  ![image](https://github.com/YeranG30/Using-Snort-for-Intrusion-Detection/assets/74067706/05b24f5f-f41b-48b1-83fa-2404a05e6b52)

## SQL Injections Overview
SQL injection (SQLi) is a type of security exploit in which an attacker adds Structured Query Language (SQL) code to a web form input box to gain access to resources or make changes to data. SQLi can be used to bypass login algorithms and retrieve, modify, or delete data. These attacks are highly prevalent due to poor coding practices and the widespread use of SQL databases in back-end software.

### Creating Detection Rules for SQL Injections
To detect SQL injections using Snort, we create rules that look for typical SQLi patterns in the network traffic. Below are the Snort rules I  designed to alert any attempts to inject SQL code via web application user input fields:

```alert tcp any any -> $HOME_NET 80 (msg:"SQL Injection - OR Detection"; content:"' OR '"; sid:1000010; rev:1;)```

```alert tcp any any -> any 80 (msg:"SQL Injection - Union Select Attempt"; content:"union+select"; nocase; sid:1000008;)```

This rule monitors for TCP traffic on port 80 where HTTP traffic occurs and looks for the specific pattern ' OR ', a common injection technique to alter SQL queries.

### Simulating an SQL Injection Attack
For demonstration purposes, you can simulate a basic SQL injection attack by sending a malicious SQL code via a web form or directly through an HTTP request. For example, using curl:

```curl -X POST -d "username=admin' OR '1'='1'--&password=" http://[Server_IP]/login```

This command attempts to log in by exploiting a common SQL injection vulnerability that bypasses authentication checks.

I also tried a more advanced Union-Based SQL Injection:

```curl -X POST -d "username=admin' UNION SELECT username, password FROM users--&password=" http://[Server_IP]/login```

### Real-Life Application and Snort Detection
In a real-world scenario, detecting such attempts early can prevent data breaches that might lead to unauthorized access to sensitive data or even complete database compromise. With Snort in place, once the defined pattern is detected in the network traffic, an alert is generated, and the security team can take immediate action.
Here's what snort detected for the basic SQL Injection: 
![image](https://github.com/YeranG30/Using-Snort-for-Intrusion-Detection/assets/74067706/31f404ff-8c75-4a31-88b4-6a6ff11effdd)

Here's what snort detected for the Union SQL Injection: 
![image](https://github.com/YeranG30/Using-Snort-for-Intrusion-Detection/assets/74067706/56e343c2-5968-414c-91f5-2e2d222c4a5a)


## FTP Misuse Overview
FTP (File Transfer Protocol) is commonly used for transferring files between systems on a network. Misuse of FTP can involve unauthorized access or brute force attacks, posing significant security risks.

### Creating Detection Rules for FTP Misuse
To detect unauthorized FTP access attempts, I employ a Snort rule that alerts on suspicious login activity:

```alert tcp any any -> any 21 (msg:"FTP Unauthorized Access Attempt"; content:"USER root"; sid:1000011;)```

This rule is designed to alert when there is an attempt to access an FTP server using the username "root," which is often targeted by attackers.

### Simulating FTP Misuse
I simulated unauthorized access by attempting to log into an FTP server with the username "root":
![image](https://github.com/YeranG30/Using-Snort-for-Intrusion-Detection/assets/74067706/e5ce25f1-6ac3-48ab-8637-903b102ee01e)

### Real-Life Application and Snort Detection
FTP servers are critical components in many business operations, facilitating the transfer of files across networks. In real-life scenarios, unauthorized access to an FTP server can lead to data breaches, intellectual property theft, or unauthorized distribution of sensitive information. Misuse of FTP credentials is a common attack vector, making it essential to monitor FTP traffic for signs of suspicious activities.

Here is what Snort detected: 
![image](https://github.com/YeranG30/Using-Snort-for-Intrusion-Detection/assets/74067706/c90a4462-c819-4c60-b59e-461c24d84690)


## Credit Card Data Leaks (DLP) Overview
Credit card data leaks involve unauthorized disclosure or transmission of credit card information, which can lead to financial fraud and identity theft.

### Creating Detection Rules for Credit Card Data Leaks
To detect potential credit card data leaks, I crafted Snort rules to identify patterns that resemble credit card numbers in network traffic:

 ```alert tcp any any -> $HOME_NET 80 (msg:"Possible Credit Card Leak"; content:"1234567890123456"; sid:1000003;)```

 ### Simulating Credit Card Information Attack 
I simulated a credit card data leak by sending fake credit card information over HTTP using curl:


```curl -X POST -d "creditcard=1234567890123456" http://[Server_IP]/submit```

### Real-Life Application and Snort Detection
After the simulated attack, here's what Snort detected: 

![image](https://github.com/YeranG30/Using-Snort-for-Intrusion-Detection/assets/74067706/86f1621b-a7e8-42f1-880c-fa175005c24c)





