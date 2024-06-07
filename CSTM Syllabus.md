# CSTM Syllabus

# ENGAGEMENT, LIFESTYLE & RISK KNOWLEDGE DOMAIN

## ENGAGEMENT LIFECYCLE

- Understand the penetration testing lifecycle, from initial client contact to the delivery of the final report and subsequent consultancy work.
- Understand the structure of a penetration test, including all relevant processes and procedures.
- Understand and follow penetration testing methodologies as required. These include methodologies defined by the tester's employer, together with recognised standards such as CHECK.
- Articulate the benefits a penetration test will bring to a client.
- Accurately convey the results of the penetration testing in both a verbal debrief and written report.

## SCOPING

- Understand the different types of testing (blackbox, whitebox, etc.) and their relative advantages and disadvantages.
- Understand client requirements and produce an accurate and adequately resourced penetration testing proposal.
- Understand scoping in Cloud environments and the impact of IaaS vs PaaS vs SaaS.
- Understand and account for technical, logistical, financial, and other constraints without compromising the effectiveness of the penetration test.

## LEGAL MATTERS

- Understand the legislation pertaining to penetration testing and can give examples of compliance/non-compliance. This includes the Computer Misuse Act 1990 and its amendments, Data Protection Act 2018, Human Rights Act 1998, Police and Justice Act 2006, Police and Criminal Evidence Act 1984, and Investigatory Powers Act 2016.
- Awareness of sector-specific regulatory issues, including NIS B4.d (Vulnerability management).

## UNDERSTANDING & MITIGATING RISK

- Understand the risks associated with a penetration test (e.g., account lockout, denial of service) and how these can be mitigated.
- Understand the importance of availability and how to reduce the risk of denial of service.
- Understand the importance of client confidentiality and the role/function of customer emergency contacts.
- Understand the impact legislation has on the penetration testing process and the ethical issues associated with penetration testing.
- Comply with non-disclosure agreements.

## ISSUE IDENTIFICATION & PROOF

- Identify false positives and false negatives and operate within the constraints of the scope of testing while keeping risk of disruption to an acceptable level.
- Produce proof-of-concept scripts to demonstrate issues.
- Chain together separate vulnerabilities to form more complex attack chains.
- Demonstrate techniques for proving issues which may fall outside of the constraints and scope in place during the engagement.

## RECORD KEEPING

- Understand the reporting requirements mandated by internal and external standards.
- Keep accurate and structured records during a penetration test, including the output of tools.
- Maintain accurate records of changes made to the systems during an assessment.
- Understand the security requirements associated with record keeping, both during the penetration test and following the delivery of the final report.
- Write a report from the information gathered during a penetration test.
- Categorize vulnerabilities with respect to recognized methodologies (e.g., CVE, BID, CVSS).

## PLATFORM PREPARATION

- Prepare the required hardware and software for a penetration test.
- Avoid data cross-contamination, e.g., by sanitizing a hard disk prior to deployment or taking an image from a master build.
- Ensure all operating system and testing tools are relevant and up-to-date.
- Ensure all commercial software is suitably licensed.
- Ensure sufficient Anti-Virus software is installed and up-to-date.
- Ensure all necessary hardware is available, including laptops, switches, media-converters, wireless devices, and cabling.

## RESULTS ANALYSIS & PRESENTATION

- Convey a detailed description of the problem, list of affected components, possible sources of further information, and a description of the risk posed in terms of confidentiality, integrity, and availability of the system and its data.
- Describe the cause of the issue, which type of attacker would most likely exploit the issue, the difficulty and likelihood of a successful exploit, and the potential impact to the customer's information systems and data, preferably in terms of CIA.
- Provide detailed recommendations for remediation, drawing upon extensive product-specific knowledge where possible and providing suitable general recommendations where not (senior or principal responsibility).
- Convey both verbal and written summaries of a security test to technical and non-technical audiences.
- Classify/rank findings using numerical and/or distinct risk levels (High, Medium, Low, etc.) in line with how the client interprets risk within its business.

---

# CORE TECHNICAL KNOWLEDGE DOMAIN

## IP PROTOCOLS

- Understand IPv4 and IPv6 and their associated security attributes.
- Understand common IP/Ethernet protocols and their associated security attributes, including TCP, UDP, ICMP, ARP, DHCP, DNS, CDP, HSRP, VRRP, VTP, STP, TACACS+.
- Understand the security implications of using clear-text protocols, such as Telnet and FTP.

## FILE SYSTEM PERMISSIONS & SYSTEM PROCESSES

- Understand and demonstrate the manipulation of file system permissions on UNIX-like and Windows operating systems.
- Find "interesting" files on an operating system, e.g., those with insecure or "unusual" permissions, or containing user account passwords.
- Identify running processes on UNIX-like and Windows operating systems and exploit vulnerabilities to escalate privileges.
- Understand technical, logistical, financial, and other constraints and take these into account without compromising the effectiveness of the penetration test.
- Detect and manipulate weak registry ACLs.

## CRYPTOGRAPHY

- Understand cryptography and its use in a networked environment.
- Understand common encrypted protocols and software applications, such as SSH, SSL, IPSEC, and PGP.
- Understand wireless protocols that support cryptographic functions, including WEP, WPA, WPA2, TKIP, EAP, LEAP, PEAP. Recognize their associated security attributes and how they can be attacked.
- Distinguish between symmetric and asymmetric cryptography and provide examples of each.
- Recognize common cryptographic algorithms, such as DES, 3DES, RSA, RC4, and AES, including their security attributes and how they can be attacked.
- Understand common hash functions, such as MD5, SHA1, and SHA256, including their security attributes and how they can be attacked.
- Understand different authentication methods such as passwords and certificates.
- Understand the generation and role of HMACs.
- Understand PKI and the concepts of IKE, Certificate Authorities, and trusted third parties.
- Differentiate between encoding and encrypting.
- Understand the dangers of implementing custom cryptography.
- Understand the differences between encryption modes (EBC, CBC, GCM, etc.).
- Follow best practices around key management and identify and exploit weaknesses in custom cryptography.

## PIVOTING

- Understand the concept of pivoting through compromised devices.
- Demonstrate pivoting through a number of devices to gain access to targets on a distant subnet.
- Employ Network Pivoting Techniques, e.g., Windows netsh Port Forwarding, SSH, SOCKS Proxy, Local Port Forwarding, Remote Port Forwarding, Proxychains, GraphTCP, Web SOCKS - reGeorg, Metasploit, sshuttle, chisel, SharpChisel, gost, Rpivot, RevSocks, plink, ngrok.
- Understand Basic Pivoting Types: Listen - Listen, Listen - Connect, Connect - Connect.

## USING TOOLS & INTERPRETING OUTPUT

- Use a variety of tools during a penetration test, selecting the most appropriate tool to meet a particular requirement.
- Understand the limitations of automated testing.
- Interpret and understand the output of tools, including those used for port scanning, vulnerability scanning, enumeration, exploitation, and traffic capture.
- Identify when tool output can and cannot be trusted.
- Demonstrate an approach to verifying tool output.
- Effectively use command line during assurance testing.
- Demonstrate the ability to carry out testing when tools are not available or functional.

## PACKET GENERATION

- Understand the different types of packets that are likely to be encountered during a penetration test.
- Generate arbitrary packets, including TCP, UDP, ICMP, and ARP, modifying packet parameters as required, e.g., source and destination IP addresses, source and destination ports, and TTL.
- Understand ARP spoofing and demonstrate this technique in a safe and reliable way.

## PORT SCANNING

- Understand different TCP connection states.
- Demonstrate active techniques for discovery of nodes on a network, such as SYN and TCP-Connect scanning, FIN/NULL and XMAS scanning, UDP port scanning, TCP ping scanning, and ICMP scanning.

## SERVICE IDENTIFICATION

- Identify the network services offered by a host by banner inspection.
- State the purpose of an identified network service and determine its type and version.
- Understand the methods associated with unknown service identification, enumeration, and validation.
- Apply advanced analysis techniques for unknown services and protocols.

## FINGERPRINTING

- Understand active and passive operating system fingerprinting techniques and demonstrate their use during a penetration test.

## TRAFFIC FILTERING & ACCESS CONTROL

- Understand network traffic filtering and where this may occur in a network.
- Know the devices and technology that implement traffic filtering, such as firewalls, and can advise on their configuration.
- Demonstrate methods by which traffic filters can be bypassed.
- Understand network access control systems, such as 802.1x and MAC address filtering, and demonstrate how these technologies can be bypassed.

## PATCH LEVELS

- Understand Microsoft patch management strategies and tools, including Microsoft Systems Management Server (SMS), Microsoft Software Update Service (SUS), Microsoft Windows Server Update Services (WSUS), and Microsoft Baseline Security Analyser (MBSA).
- Demonstrate how network access control systems, such as 802.1x and MAC address filtering, can be bypassed.

## BUILD REVIEW

- Perform a security build review of common operating systems.
- Test against common build standards such as CIS benchmarks.
- Map technical controls to a customer's business requirements and intents, justifying the need to tighten or relax them where necessary to meet business needs.

## HARDWARE SECURITY

- Understand the concepts behind common microprocessor vulnerabilities such as Spectre and Meltdown.
- Understand the concepts behind side-channel attacks such as timing analysis and power analysis.
- Understand how side-channel attacks can aid cryptanalysis and otherwise expose sensitive data.
- Understand common risks associated with Bluetooth, including Bluesnarling, Bluejacking, and Bluebugging.

---

# INFORMATION GATHERING KNOWLEDGE DOMAIN

## DOMAIN REGISTRATION

- Understands the format of a WHOIS record and can obtain such records to derive information about an IP address and/or domain.

## DNS

- Understands the Domain Name Service (DNS), including queries and responses, zone transfers, and the structure and purpose of records such as SOA, NS, MX, A, AAAA, CNAME, PTR, TXT (including use in DMARC policies), HINFO, and SVR.
- Can demonstrate how a DNS server can be queried to obtain detailed information from these records and to reveal other information that might indicate the presence of security vulnerabilities.
- Can identify the presence of dangling DNS entries and understands the associated security vulnerabilities, such as susceptibility to subdomain takeover.

## WEBSITE ANALYSIS

- Can interrogate a website to obtain information about a target network, such as the name and contact details of the network administrator.
- Can analyse information from a target website, both from displayed content and from within the HTML source.

## SEARCH ENGINES, NEWS GROUPS & MAILING LISTS

- Can use search engines, news groups, mailing lists, and other services to obtain information about a target network, such as the name and contact details of the network administrator.
- Can analyse e-mail headers to identify system information.

## INFORMATION LEAKAGE

- Can obtain information about a target network from information leaked in email headers, HTML meta tags, and other locations, such as internal network IP addresses.

## BANNER GRABBING

- Can enumerate services, their software types, and versions using banner grabbing techniques.

## SNMP

- Can retrieve information from SNMP services and understands the MIB structure pertaining to the identification of security vulnerabilities.

## PHISHING

- Understands common phishing techniques and how these can lead to compromise.
- Recognizes when vulnerabilities discovered elsewhere can be leveraged as part of a phishing campaign.

---

# NETWORKING KNOWLEDGE DOMAIN

## NETWORK ARCHITECTURE

- Can interpret logical network diagrams.
- Understands the various network types that could be encountered during a penetration test, such as CAT 5/Fibre, 10/100/1000base T, and Wireless (802.11).
- Understands the difference between LAN and WAN, internal (RFC 1918) IP ranges, and basics of IPv6 addressing.
- Understands the security implications of copper cables vs. fibre, tiered architectures, DMZs, and air gaps.
- Understands the security implications of shared media, switched networks, VLANs, and the core principles and concepts of a Software Defined Network (SDN), including disassociation of data and control planes, the role of controllers in the control plane, and the common security risks of the application plane and the northbound API.

## NETWORK ROUTING

- Understands default gateways and static routes.
- Can configure static IPs and routes.
- Understands network routing and its associated protocols, including RIP, OSPF, EIGRP, BGP, and IGMP.
- Understands the security attributes of these protocols.

## NETWORK MAPPING

- Can demonstrate the mapping of a network using a range of tools such as traceroute, ping, and by querying active searches such as DNS and SNMP servers.
- Can accurately identify all hosts on a target network that meet a defined set of criteria, e.g., to identify all FTP servers or CISCO routers.
- Can present the map as a logical network diagram, detailing all discovered subnets and interfaces, including routers, switches, hosts, and other devices.

## MANAGEMENT PROTOCOLS

- Understands and can demonstrate the use of protocols often used for the remote management of devices, including Telnet, SSH, HTTP/HTTPS, SNMP, Cisco Reverse Telnet, TFTP, NTP, RDP, and VNC.
- Can analyse e-mail headers to identify system information.

## TRAFFIC ANALYSIS

- Can intercept and monitor network traffic, capturing it to disk in a format required by analysis tools (e.g., PCAP).
- Understands and can demonstrate how network traffic can be analysed to recover user account credentials and detect vulnerabilities that may lead to the compromise of a target device.

## CONFIGURATION ANALYSIS

- Understands configuration files of Cisco routers and switches and can advise on how their security can be improved (most common features such as access-lists and enabled services).
- Can interpret the configuration files of other network devices, including those produced by a variety of vendors.

## ROUTERS & SWITCHERS

- Understands and can demonstrate the exploitation of vulnerabilities in routers and switches, including the use of protocols such as Telnet, SSH, HTTP/HTTPS, TFTP, and SNMP.

## VOIP

- Understands VoIP services, such as SIP, and can identify and fingerprint devices offering these services.

---

# MICROSOFT WINDOWS KNOWLEDGE DOMAIN

## RECONNAISSANCE

- Can identify Windows hosts on a target network.
- Can identify forests, domains, domain controllers, domain members, and workgroups.
- Can enumerate accessible Windows shares.
- Can identify and analyse internal browse lists.
- Can identify and analyse Service Principle Names.
- Understands and can identify the different types of domain trusts, including one-way and two-way trusts, explicit and transitive trusts.

## ENUMERATION

- Can perform user and group enumeration on target systems and domains using protocols including NetBIOS, LDAP, and SNMP.
- Can obtain other information such as password policies.
- Can perform analysis of an AD (Global Catalogue, Master Browser, and FSMO).
- Can perform SID enumeration and RID cycling.

## ACTIVE DIRECTORY

- Understands Active Directory structure.
- Understands the reliance of Active Directory on DNS and LDAP.
- Understands the difference between local and domain users.
- Understands the security weaknesses of shared local administrative accounts.
- Understands Group Policy and Local Security Policy.
- Can manipulate user accounts to gain further access to a target system, e.g., by escalating privileges from a domain user to a domain admin.
- Can demonstrate the recovery of password hashes when given physical access to a Windows host.
- Can demonstrate offline password cracking using dictionary and brute-force attacks, including the use of rainbow tables.
- Can identify inappropriate accounts or group memberships.
- Can perform basic SPN/Kerberoasting.
- Can exploit shared local administrative accounts by passing-the-hash.
- Can obtain passwords from Group Policy Preferences.
- Can perform more advanced Kerberos attacks (golden/silver tickets, etc).
- Can identify inappropriate or dangerous Group Policies or permissions.
- Understands Active Directory roles (Global Catalogue, Master Browser, FSMO).

## PASSWORDS

- Understands password policies, including complexity requirements and lock-out mechanisms.
- Understands how to avoid causing a denial of service by locking out accounts.
- Understands Windows password hashing algorithms and their associated security attributes.
- Can demonstrate how passwords are stored, protected, and can be recovered.
- Can demonstrate offline password cracking using dictionary and brute-force attacks, including the use of rainbow tables.
- Can demonstrate the recovery of password hashes when given physical access to a Windows host.

## REMOTE VULNERABILITIES

- Understands the use of tools and techniques to identify new OS and software vulnerabilities.
- Can demonstrate the remote exploitation of Windows operating system and third-party software application vulnerabilities.
- Understands the techniques used to develop exploit code for existing and new vulnerabilities.

## LOCAL VULNERABILITIES

- Can demonstrate local privilege escalation techniques, e.g., through the manipulation of insecure file system or service permissions.
- Understands the difference between "Local Service," "Network Service," and "Local System."
- Can extract service credentials from LSA secrets.

## POST EXPLOITATION

- Can perform common post-exploitation activities, including obtaining password hashes (both from the local SAM and cached credentials), obtaining locally stored clear-text passwords, cracking password hashes, obtaining patch levels, deriving a list of missing security patches, reverting to a previous state, and facilitating lateral and horizontal movement.

## DESKTOP LOCKDOWN

- Can demonstrate techniques to break out of a locked-down Windows desktop or Citrix environment.
- Can perform privilege escalation techniques from a desktop environment.

## PATCH MANAGEMENT

- Understands patching in air-gapped environments.
- Understands common Windows patch management strategies, including SMS, SUS, and WSUS.

## EXCHANGE

- Can identify and analyse Microsoft Exchange servers.
- Can perform common attack vectors for Microsoft Exchange Server.

## COMMON WINDOWS APPLICATIONS

- Can identify and leverage significant vulnerabilities in common Windows applications for which there is public exploit code available.

---

# UNIX SECURITY KNOWLEDGE DOMAIN

## RECONNAISSANCE

- Can identify Unix hosts on a target network.

## ENUMERATION

- Can demonstrate and explain the enumeration of data from a variety of common network services on various platforms including:
    - Filesystems or resources shared remotely, such as NFS and SMB.

## SMTP, SSH, Telnet, SNMP, and RID cycling.

- Is aware of legacy user enumeration techniques such as rusers and rwho.
- Can enumerate RPC services and identify those with known security vulnerabilities.

## PASSWORDS

- Understands users, groups, and password policies, including complexity requirements and lock-out mechanisms.
- Understands how to avoid causing a denial of service by locking-out accounts.
- Understands UNIX password hashing algorithms and their associated security attributes.
- Can demonstrate how passwords are stored and protected and how they can be recovered.
- Can demonstrate offline password cracking using dictionary and brute-force attacks.
- Can demonstrate the recovery of password hashes when given physical access to a UNIX host.
- Understands the format of the passwd, shadow, group, and gshadow files.

## REMOTE VULNERABILITIES

- Can demonstrate the remote exploitation of Solaris and Linux operating system vulnerabilities.

## LOCAL VULNERABILITIES

- Can demonstrate local privilege escalation techniques, e.g., through the manipulation of insecure file system permissions.
- Can demonstrate the local exploitation of Solaris and Linux operating system vulnerabilities.

## POST EXPLOITATION

- Can demonstrate common post-exploitation activities, including:
    - Obtaining locally stored clear-text passwords.
    - Password recovery (exfiltration and cracking).
    - Lateral movement.
    - Checking OS and third-party software application patch levels.
    - Deriving a list of missing security patches.

## Reversion of OS and software components to a previous state.

## FTP/TFTP

- Understands FTP and can demonstrate how a poorly configured FTP server can be exploited, e.g., downloading arbitrary files, uploading and overwriting files, and modifying file system permissions.
- Understands the security implications of anonymous FTP access.
- Understands TFTP and can demonstrate how a poorly configured TFTP server can be exploited, e.g., downloading arbitrary files.
- Can exploit TFTP within a Cisco environment.

## NFS

- Understands NFS and its associated security attributes and can demonstrate how exports can be identified.
- Can demonstrate how a poorly configured NFS service can lead to the compromise of a server, allow a user to escalate privileges, and/or gain further access to a host, e.g., through the creation of SUID-root files, the modification of files and file system permissions, and UID/GID manipulation.
- Understands the concepts of root squashing, nosuid, and noexec options.
- Understands how NFS exports can be restricted at both a host and file level.

## SSH

- Understands that SSH can be used for port forwarding and file transfer.
- Understands SSH and its associated security attributes, including different versions of the protocol, version fingerprinting, and how the service can be used to provide a number of remote access services.
- Can demonstrate how trust relationships can lead to the compromise of a server, allow a user to escalate privileges and/or gain further access to a host, e.g., through the use, creation, or modification of ~/.ssh/authorized_keys files.
- Can demonstrate the ability to use forward and reverse port forwarding.

## X COMMAND

- Understands X and its associated security attributes, and can demonstrate how insecure sessions can be exploited, e.g., by obtaining screenshots, capturing keystrokes, and injecting commands into open terminals.
- Can describe the differences between X and %SYSRC and the typical use cases within a test.

## SENDRAIL/SMTP

- Understands and can demonstrate valid username discovery via EXPN and VRFY.
- Is aware of recent sendmail vulnerabilities and the ability to exploit them if possible.

## PATCHING

- Understands backported patches and the effect they have on scanning tools.
- Understands enterprise patching strategies for Linux.
- Understands patching in air-gapped environments.
- Understands the security implications of installing software outside of the OS package manager.

## SUDO

- Understands the purpose of using sudo rather than logging in as root.
- Understands the difference between sudo and su.
- Demonstrates the ability to exploit weak sudo configuration.

---

# DATABASES KNOWLEDGE DOMAIN

## Reconnaissance

- Understands and can demonstrate the remote exploitation of Microsoft SQL Server.
- Knows how to gain access to a Microsoft SQL Server using default account credentials and insecure passwords.
- Can identify and extract useful information stored within a database, such as user account names and passwords, and can recover passwords where possible.
- Can use stored procedures following the compromise of a Microsoft SQL Server to execute system commands, escalate privileges, read/write from/to the file system, and/or gain further access to a host.
- Understands and can demonstrate the remote exploitation of an Oracle database.

## ORACLE

- Understands the security attributes of the Oracle TNS Listener service.
- Can demonstrate how to obtain the software version and patch status from an Oracle database.
- Understands and can demonstrate how access can be gained to an Oracle database server through the use of default accounts, credentials, and insecure passwords.
- Can identify and extract useful information stored within an Oracle database, such as user account names and passwords, and recover passwords where possible.
- Following the compromise of an Oracle database server, can use stored procedures to execute system commands, escalate privileges, read/write from/to the file system, and/or gain further access to a host.

## OTHER DATABASES

- Understands and can demonstrate the remote exploitation of other common SQL database servers, such as MySQL and PostgreSQL.
- Understands and can demonstrate the remote exploitation of common no-SQL database servers, such as MongoDB.
- Can demonstrate how access can be gained to such database servers through the use of default accounts and insecure passwords.
- Can identify and extract useful information stored within a database, such as user account names and passwords, and recover passwords where possible.

## DATABASE CONNECTIVITY

- Understands common connection and authentication methods used by web applications to connect to database servers.
- Can recognize common database connection string formats, such as JDBC.

## SQL SERVER

- Can identify running databases using the SQL browser service.
- Understands the difference between local SQL Server accounts and integrated authentication, and the security implications of both.
- Can demonstrate the ability to execute operating system commands without xp_cmdshell.

---

# WEB TECHNOLOGIES KNOWLEDGE DOMAIN

## WEB SERVERS

- Can identify web servers on a target network and remotely determine their type and version.
- Has knowledge of vulnerabilities in common application frameworks, servers, and technologies including .NET, J2EE, Coldfusion, Ruby on Rails, and NodeJS.
- Understands the purpose, operation, limitations, and security attributes of web proxy servers.
- Can demonstrate the remote exploitation of web servers.
- Understands the concepts of virtual hosting and web proxies.

## RECONNAISSANCE

- Can use spidering tools and understands their relevance in web application testing for discovering linked content.
- Can demonstrate forced browsing techniques to discover default or unlinked content.
- Can identify functionality within client-side code.

## PROTOCOLS AND METHODS

- Understands all HTTP methods and response codes.
- Understands HTTP header fields relating to security features.
- Can demonstrate the use of web protocols including HTTP, HTTPS, and Web Sockets.
- Can demonstrate HTTP Request Smuggling.

## LANGUAGES

- Understands common web markup and programming languages, including .NET, ASP Classic, Perl, PHP, JSP, Python, and JavaScript.
- Can demonstrate how the insecure implementation of software developed using these languages can be exploited.

## APIs

- Can demonstrate the use of web-based APIs to remotely access remote services.
- Understands the use of tools and techniques to identify new OS and software vulnerabilities.
- Understands common authentication techniques used in web APIs, e.g., API keys.
- Can demonstrate the use of relevant tools to test APIs, such as SoapUI and Postman.
- Can demonstrate how the insecure implementation of web-based APIs can be exploited.
- Understands different common payload formats such as XML and JSON.
- Understands how to interpret definition files, e.g., WSDL and Swagger.

## INFORMATION GATHERING

- Can gather information from a website and application markup or programming language, including hidden form fields, database connection strings, user account credentials, developer comments, and external and/or authenticated-only URLs.
- Can gather information about a website and application from the error messages it generates.

## AUTHENTICATION

- Understands common authentication vulnerabilities, including transport of credentials over an unencrypted channel, testing for username enumeration, brute-force testing, authentication bypass, session hijacking, insecure password reset features, insufficient logout timeout/functionality, vulnerable CAPTCHA controls, race conditions, and lack of MFA.

## AUTHORISATION

- Understands common pitfalls associated with the design and implementation of application authorization mechanisms.

## INPUT VALIDATION

- Understands the importance of input validation and how it can be implemented, e.g., allow-lists, deny-lists, and regular expressions.
- Understands the need for server-side validation and the flaws associated with client-side validation.

## FUZZING

- Understands cross-site-scripting (XSS) and can demonstrate the launching of a successful XSS attack.
- Understands the difference between persistent (stored) and reflected XSS.

## INJECTION

- Can demonstrate the ability to identify, explain, and prove the existence of various types of network infrastructure vulnerabilities and exposures, including XXE, XML Injection, LDAP Injection, ORM injection, SSI injection, XPath injection, IMAP/SMTP injection, Code injection, and OS Commanding.

## SQL INJECTION

- Can identify and exploit SQL injection.
- Can exploit Union-based injection.
- Can exploit SQL injection to execute operating system commands or read files.

## BLIND SQL INJECTION

- Can determine the existence of a blind SQL injection condition in a web application.
- Can exploit a blind SQL injection vulnerability.

## SESSIONS

- Can identify JWT issues.
- Can exploit "none" signature or lack of signature checking in JWTs.
- Understands the difference between HMAC and public key JWTs.
- Can identify the session control mechanism used within a web application.
- Understands and can exploit session fixation vulnerabilities.
- Understands the security implications of session IDs exposed in URLs.
- Understands the role of sessions in CSRF attacks.
- Can identify low entropy in sessions.
- Can brute-force weak HMAC keys in JWTs.

## CRYPTOGRAPHY

- Understands how cryptography can be used to protect data in transit and at rest, both on the server and client side.
- Understands the concepts of TLS and can determine whether a TLS-enabled web server has been configured in compliance with best practices, supporting recommended ciphers and key lengths.
- Can identify and exploit encoded and cryptographic values, e.g., Base64 and MD5 hashes.

## PARAMETER MANIPULATION

- Understands parameter manipulation techniques, particularly the use of client-side proxies.

## DIRECTORY TRAVERSAL

- Understands and can identify directory traversal vulnerabilities within applications.

## FILE UPLOADS

- Understands and can identify common vulnerabilities with file upload capabilities within applications.
- Understands the role of MIME types in relation to file upload features.
- Can generate malicious payloads in a variety of common file formats.

## CRLF ATTACKS

- Can generate malicious payloads in a variety of common file formats.

## APPLICATION LOGIC FLAWS

- Can assess and exploit vulnerabilities within the functional logic, function access control, and business logic of an application.

---

# PHYSICAL ACCESS & SECURITY KNOWLEDGE DOMAIN

## LOCKS

- Understands how locks can be used to restrict access to computer hardware.

## TAMPER SEALS

- Understands how tamper seals can be used to deter access to computer hardware.

## PLATFORM INTEGRITY

- Understands platform integrity technologies, such as Trusted Platform Module (TPM).

## BOOT SEQUENCE

- Understands and can demonstrate the remote exploitation of common no-SQL database servers, such as MongoDB.

## DISK ENCRYPTION

- Understands the security implications of unencrypted storage devices, such as hard disks.
- Can demonstrate how data can be recovered from unencrypted storage devices and how such data can be manipulated to introduce vulnerabilities into an operating system.

## RECOVERY FUNCTIONALITY

- Understands the security attributes of operating system recovery functionality, e.g., Windows Recovery Console and Safe Mode.

## AUTHENTICATION

- Understands multi-factor authentication systems, such as tokens and SMS.
- Understands types of biometrics and how they can be applied.
- Understands the concept of one-time pads.
- Understands the use of digital certificates as an authentication mechanism.
- Understands the concept of contactless RFID smart cards.

---

# VIRTUALISATION & CONTAINERISATION

## VIRTUALISATION PLATFORMS

- Can identify use of popular virtualisation technologies, including VMware, Microsoft HyperV, Citrix, and Oracle Virtual Box.
- Understands common vulnerabilities found in hypervisors, including exposure of the management interface, use of default or insecure credentials, and common high-profile CVEs.
- Understands the inherent risks in shared virtualised environments, such as shared memory space.

## VIRTUAL MACHINE ESCAPE

- Understands and can demonstrate common techniques for escaping a virtualised environment, including:
    - Directory traversal in shared folders.
    - Virtual device communication breakout.
    - Public CVEs relating to memory corruption.

## SNAPSHOTS

- Can demonstrate how to take snapshots and techniques for recovering key sensitive information.
- Understands the security implications of reverting a VM to a previous state.
- Understands the sensitive nature of snapshot files and the need to restrict access.

## CONTAINERISATION

- Understands the key differences between virtualisation and containerisation.
- Can identify and interrogate running containers on a host.
- Understands the concepts of layered filesystems and how to extract and analyse specific layers within an image.
- Can identify common vulnerabilities and weaknesses present in containers, including missing security patches, weak file permissions, insufficient or lack of resource quotas, and the presence of sensitive information in environment variables, running processes, or filesystem.
- Understands and can analyse Dockerfile files to uncover weaknesses in static images, including:
    - Use of unencrypted connections for performing downloads.
    - Use of overly generous permissions, e.g., running as the root user.
    - Inclusion of sensitive information, e.g., passwords or private keys.
    - Unnecessary exposure of ports.
- Understands the security implications of using third-party containers.
- Understands how to manage containers throughout their lifecycle.
- Understands the functionality offered by Kubernetes, including security implications and different deployment models such as OpenShift, EKS/AKS, and Docker on a single server.

---

# TYPICAL INDUSTRY ROLES

## AUTHORISATION

- Understands the importance of obtaining authorisation from cloud hosting providers and the potential effects on permitted types of testing during engagements.

## VIRTUAL PRIVATE CLOUDS

- Understands the concepts of a Virtual Private Cloud (VPC) and the implications on performing security assessments.
- Can competently assess resources within a private cloud-hosted environment, advising on any necessary temporary changes that may be needed (e.g., creation of bastion hosts, changes to Security Groups/firewalls).

## LOGGING & MONITORING

- Can analyse logging configuration within a cloud environment and advise on improvements.
- Can analyse the configuration of resource monitoring and alarm generation and advise on improvements.

## IDENTITY AND ACCESS MANAGEMENT

- Understands the identity and access management models of popular cloud providers.
- Can assess roles and policies to identify weaknesses relating to insecure permissions.

## DENIAL OF SERVICE AND RESOURCE EXHAUSTION

- Understands how (Distributed) Denial of Service attacks are performed and the protective measures available in cloud environments.
- Understands the financial implications of excessive resource consumption.

## CLOUD ARCHITECTURE

- Understands the differences between cloud and on-premises architecture.
- Understands how to link between the two.
- Understands the different security responsibility boundaries between IaaS, PaaS, and SaaS.

## AZURE

- Can identify and understand the key administrative roles in Azure.
- Can identify the Azure metadata service.
- Understands and reviews conditional access policies.
- Understands the differences between AD, Azure AD DS, and Azure AD.

## AWS

- Can identify and understand the key administrative roles in AWS.
- Understands the difference between roles and policies.
- Can identify the AWS metadata service.

## MOBILE DEVICE MANAGEMENT (MDM)

- Understands the purpose of MDM solutions and the functionality they offer.
- Can review MDM configuration policies.

---

# SECURE DEVELOPMENT OPERATIONS KNOWLEDGE DOMAIN

## SECURE CODING PRACTICES

- Understands common insecure programming practices, including:
    - Use of dangerous functions.
    - Insufficient sanitization of user-supplied data.
    - Use of outdated third-party components.
    - Logic errors.

## SECURITY AS CODE

- Understands the role of automated security testing tools as part of the development process, including:
    - Static analysis tools (SAST).
    - Dependency checking tools.
    - Dynamic analysis tools (DAST).
- Understands how automated tooling can safely and effectively be incorporated into the development pipeline.
- Can identify and advise on common security misconfigurations of these tools.

## INFRASTRUCTURE AS CODE

- Understands the role of tools to automate the building, configuration, and deployment of infrastructure, including:
    - Terraform.
    - Puppet.
    - Ansible.
    - Chef.
- Can identify and advise on common security misconfigurations of these tools.

## CODE REPOSITORY SECURITY

- Can identify and advise on issues relating to weakly protected code repositories, for example:
    - Openly exposed repositories containing closed-source code.
    - Weak or insufficiently protected credentials.
- Understands the security implications of storing sensitive information in source code repositories, such as passwords, private cryptographic keys, or API keys.