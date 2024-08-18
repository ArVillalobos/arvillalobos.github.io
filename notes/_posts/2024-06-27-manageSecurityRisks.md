---
layout: post
title: Manage Security Risks
image: /assets/img/notes/SecurityRisks.png
related_posts:
  - notes/_posts/2024-06-27-cyberFundamentals.md
sitemap: false
categories: notes
---

# Manage Security Risks

The steps in the Risk Management Framework (RMF) are prepare, categorize, select, implement, assess, authorize, and monitor.

* toc
{:toc}

### Key impacts of threats, risks, and vulnerabilities:

* Damage to reputation

* Financial damage

* Identity theft



### Some common strategies used to manage risks include:

* Acceptance: Accepting a risk to avoid disrupting business continuity

* Avoidance: Creating a plan to avoid the risk altogether

* Transference: Transferring risk to a third party to manage

* Mitigation: Lessening the impact of a known risk


## Threats
A threat is any circumstance or event that can negatively impact assets. As an entry-level security analyst, your job is to help defend the organization’s assets from inside and outside threats. Therefore, understanding common types of threats is important to an analyst’s daily work. As a reminder, common threats include:

* **Insider threats:** Staff members or vendors abuse their authorized access to obtain data that may harm an organization.

* **Advanced persistent threats (APTs):** A threat actor maintains unauthorized access to a system for an extended period of time.


## Risks
A risk is anything that can impact the confidentiality, integrity, or availability of an asset. A basic formula for determining the level of risk is that risk equals the likelihood of a threat. One way to think about this is that a risk is being late to work and threats are traffic, an accident, a flat tire, etc. 

There are different factors that can affect the likelihood of a risk to an organization’s assets, including:

* **External risk:** Anything outside the organization that has the potential to harm organizational assets, such as threat actors attempting to gain access to private information

* **Internal risk:** A current or former employee, vendor, or trusted partner who poses a security risk

* **Legacy systems:** Old systems that might not be accounted for or updated, but can still impact assets, such as workstations or old mainframe systems. For example, an organization might have an old vending machine that takes credit card payments or a workstation that is still connected to the legacy accounting system.

* **Multiparty risk:** Outsourcing work to third-party vendors can give them access to intellectual property, such as trade secrets, software designs, and inventions.

* **Software compliance/licensing:** Software that is not updated or in compliance, or patches that are not installed in a timely manner


## Vulnerabilities
A vulnerability is a weakness that can be exploited by a threat. Therefore, organizations need to regularly inspect for vulnerabilities within their systems. Some vulnerabilities include:

* **ProxyLogon:** A pre-authenticated vulnerability that affects the Microsoft Exchange server. This means a threat actor can complete a user authentication process to deploy malicious code from a remote location.

* **ZeroLogon:** A vulnerability in Microsoft’s Netlogon authentication protocol. An authentication protocol is a way to verify a person's identity. Netlogon is a service that ensures a user’s identity before allowing access to a website's location.

* **Log4Shell:** Allows attackers to run Java code on someone else’s computer or leak sensitive information. It does this by enabling a remote attacker to take control of devices connected to the internet and run malicious code.

* **PetitPotam:** Affects Windows New Technology Local Area Network (LAN) Manager (NTLM). It is a theft technique that allows a LAN-based attacker to initiate an authentication request.

* **Security logging and monitoring failures:** Insufficient logging and monitoring capabilities that result in attackers exploiting vulnerabilities without the organization knowing it

* **Server-side request forgery:** Allows attackers to manipulate a server-side application into accessing and updating backend resources. It can also allow threat actors to steal data.


## Frameworks
Security frameworks are guidelines used for building plans to help mitigate risk and threats to data and privacy. Frameworks support organizations’ ability to adhere to compliance laws and regulations. For example, the healthcare industry uses frameworks to comply with the United States’ Health Insurance Portability and Accountability Act (HIPAA), which requires that medical professionals keep patient information safe. 
* Cyber Threat Framework (CTF)
According to the Office of the Director of National Intelligence, the CTF was developed by the U.S. government to provide “a common language for describing and communicating information about cyber threat activity.” By providing a common language to communicate information about threat activity, the CTF helps cybersecurity professionals analyze and share information more efficiently. This allows organizations to improve their response to the constantly evolving cybersecurity landscape and threat actors' many tactics and techniques.
* International Organization for Standardization/International Electrotechnical Commission (ISO/IEC) 27001
An internationally recognized and used framework is ISO/IEC 27001. The ISO 27000 family of standards enables organizations of all sectors and sizes to manage the security of assets, such as financial information, intellectual property, employee data, and information entrusted to third parties. This framework outlines requirements for an information security management system, best practices, and controls that support an organization’s ability to manage risks. Although the ISO/IEC 27001 framework does not require the use of specific controls, it does provide a collection of controls that organizations can use to improve their security posture. 

## Controls
Security controls are safeguards designed to reduce specific security risks. Security controls are the measures organizations use to lower risk and threats to data and privacy. For example, a control that can be used alongside frameworks to ensure a hospital remains compliant with HIPAA is requiring that patients use multi-factor authentication (MFA) to access their medical records. Using a measure like MFA to validate someone’s identity is one way to help mitigate potential risks and threats to private data.

**Examples of physical controls:**

* Gates, fences, and locks

* Security guards

* Closed-circuit television (CCTV), surveillance cameras, and motion detectors

* Access cards or badges to enter office spaces

**Examples of technical controls:**

* Firewalls

* MFA

* Antivirus software

**Examples of administrative controls:**

* Separation of duties

* Authorization

* Asset classification

## National Institute of Standards and Technology (NIST) Cybersecurity Framework (CSF)

The NIST Cybersecurity Framework consists of five core functions that provide a strategic view of the lifecycle of an organization's management of cybersecurity risk. These functions are:

* **Identify:** Develop an organizational understanding to manage cybersecurity risk to systems, assets, data, and capabilities. This includes asset management, business environment, governance, risk assessment, and risk management strategy.

* **Protect:** Develop and implement appropriate safeguards to ensure the delivery of critical infrastructure services. This includes access control, awareness and training, data security, information protection processes and procedures, maintenance, and protective technology.

* **Detect:** Develop and implement appropriate activities to identify the occurrence of a cybersecurity event. This includes continuous monitoring, detection processes, and detection of anomalies and events.

* **Respond:** Develop and implement appropriate activities to take action regarding a detected cybersecurity incident. This includes response planning, communications, analysis, mitigation, and improvements.

* **Recover:** Develop and implement appropriate activities to maintain resilience plans and restore any capabilities or services that were impaired due to a cybersecurity incident. This includes recovery planning, improvements, and communications.

## OWASP

### Security principles

* Minimize attack surface area: Attack surface refers to all the potential vulnerabilities a threat actor could exploit.

* Principle of least privilege: Users have the least amount of access required to perform their everyday tasks.

* Defense in depth: Organizations should have varying security controls that mitigate risks and threats.

* Separation of duties: Critical actions should rely on multiple people, each of whom follow the principle of least privilege. 

* Keep security simple: Avoid unnecessarily complicated solutions. Complexity makes security difficult. 

* Fix security issues correctly: When security incidents occur, identify the root cause, contain the impact, identify vulnerabilities, and conduct tests to ensure that remediation is successful.

### Additional OWASP security principles

**Establish secure defaults**
This principle means that the optimal security state of an application is also its default state for users; it should take extra work to make the application insecure. 

**Fail securely**
Fail securely means that when a control fails or stops, it should do so by defaulting to its most secure option. For example, when a firewall fails it should simply close all connections and block all new ones, rather than start accepting everything.

**Don’t trust services**
Many organizations work with third-party partners. These outside partners often have different security policies than the organization does. And the organization shouldn’t explicitly trust that their partners’ systems are secure. For example, if a third-party vendor tracks reward points for airline customers, the airline should ensure that the balance is accurate before sharing that information with their customers.

**Avoid security by obscurity**
The security of an application should not rely on keeping the source code secret. Its security should rely upon many other factors, including reasonable password policies, defense in depth, business transaction limits, solid network architecture, and fraud and audit controls.


## Audit checklist
It’s necessary to create an audit checklist before conducting an audit. A checklist is generally made up of the following areas of focus:

### Identify the scope of the audit

The audit should:

* List assets that will be assessed (e.g., firewalls are configured correctly, PII is secure, physical assets are locked, etc.) 

* Note how the audit will help the organization achieve its desired goals

* Indicate how often an audit should be performed

* Include an evaluation of organizational policies, protocols, and procedures to make sure they are working as intended and being implemented by employees

### Complete a risk assessment

* A risk assessment is used to evaluate identified organizational risks related to budget, controls, internal processes, and external standards (i.e., regulations).

### Conduct the audit

* When conducting an internal audit, you will assess the security of the identified assets listed in the audit scope.

### Create a mitigation plan

* A mitigation plan is a strategy established to lower the level of risk and potential costs, penalties, or other issues that can negatively affect the organization’s security posture. 

### Communicate results to stakeholders

* The end result of this process is providing a detailed report of findings, suggested improvements needed to lower the organization's level of risk, and compliance regulations and standards the organization needs to adhere to. 


## Control categories

Controls within cybersecurity are grouped into three main categories:
* Administrative/Managerial controls
* Technical controls
* Physical/Operational controls

**Administrative/Managerial controls** address the human component of
cybersecurity. These controls include policies and procedures that define how an
organization manages data and clearly defines employee responsibilities, including
their role in protecting the organization. While administrative controls are typically
policy based, the enforcement of those policies may require the use of technical or
physical controls.
**Technical controls** consist of solutions such as firewalls, intrusion detection systems
(IDS), intrusion prevention systems (IPS), antivirus (AV) products, encryption, etc.
Technical controls can be used in a number of ways to meet organizational goals and
objectives.
**Physical/Operational controls** include door locks, cabinet locks, surveillance
cameras, badge readers, etc. They are used to limit physical access to physical assets
by unauthorized personnel.

## Control types
Control types include, but are not limited to:
1. Preventative
2. Corrective
3. Detective
4. Deterrent


## Administrative Controls

|Control Name|Control Type|Control Purpose|
|-|-|-|
|Least Privilege|Preventative|Reduce risk and overall impact of malicious insider or compromised accounts|
|Disaster recovery plans|Corrective|Provide business continuity|
|Password policies|Preventative|Reduce likelihood of account compromise through brute force or dictionary attack techniques|
|Access control policies|Preventative|Bolster confidentiality and integrity by defining which groups can access or modify data|
|Account management policies|Preventative|"Managing account lifecycle, reducing attack surface, and limiting overall impact from disgruntled former employees and default account usage"|
|Separation of duties|Preventative|Reduce risk and overall impact of malicious insider or compromised accounts|

## Technical Controls

|Control Name|Control Type|Control Purpose|
|-|-|-|
|Firewall|Preventative|To filter unwanted or malicious traffic from entering the network|
|IDS/IPS|Detective|To detect and prevent anomalous traffic that matches a signature or rule|
|Encryption|Deterrent|Provide confidentiality to sensitive information|
|Backups|Corrective|Restore/recover from an event|
|Password management|Preventative|Reduce password fatigue|
|Antivirus (AV) software|Corrective|Detect and quarantine known threats|
|"Manual monitoring, maintenance, and intervention"|Preventative|"Necessary to identify and manage threats, risks, or vulnerabilities to out-of-date systems"|



## Physical Controls

|Control Name|Control Type|Control Purpose|
|-|-|-|
|Time-controlled safe|Deterrent|Reduce attack surface and overall impact from physical threats|
|Adequate lighting|Deterrent|Deter threats by limiting “hiding” places|
|Closed-circuit television (CCTV)|Preventative/Detective|"Closed circuit television is both a preventative and detective control because it’s presence can reduce risk of certain types of events from occurring, and can be used after an event to inform on event conditions"|
|Locking cabinets (for network gear)|Preventative|Bolster integrity by preventing unauthorized personnel and other individuals from physically accessing or modifying network infrastructure gear|
|Signage indicating alarm service provider|Deterrent|Deter certain types of threats by making the likelihood of a successful attack seem low|
|Locks|Deterrent/Preventative|"Bolster integrity by deterring and preventing unauthorized personnel, individuals from physically accessing assets"|
|"Fire detection and prevention (fire alarm, sprinkler system, etc.)"|Detective/Preventative|"Detect fire in physical location and prevent damage to physical assets such as inventory, servers, etc.":|

## incident and vulnerability playbooks

* **Preparation:**Before incidents occur, mitigate potential impacts on the organization by documenting, establishing staffing plans, and educating users. 

* **Detection and Analysis:**Detect and analyze events by implementing defined processes and appropriate technology.

* **Containment:**Prevent further damage and reduce immediate impact of incidents.

* **Eradication and Recovery:**Completely remove artifacts of the incident so that an organization can return to normal operations.

* **Post-Incident activity:**Document the incident, inform organizational leadership, and apply lessons learned.

* **Coordination:**Report incidents and share information throughout the response process, based on established standards.


# Glossary

## A
* Assess: The fifth step of the NIST RMF that means to determine if established controls are implemented correctly
* Asset: An item perceived as having value to an organization
* Attack vectors: The pathways attackers use to penetrate security defenses
* Authentication: The process of verifying who someone is
* Authorization: The concept of granting access to specific resources in a system
* Authorize: The sixth step of the NIST RMF that refers to being accountable for the security and privacy risks that might exist in an organization
* Availability: The idea that data is accessible to those who are authorized to access it

## B
* Biometrics: The unique physical characteristics that can be used to verify a person’s identity
*  Business continuity: An organization's ability to maintain their everyday productivity by establishing risk disaster recovery plans

## C
* Categorize: The second step of the NIST RMF that is used to develop risk management processes and tasks
* Chronicle: A cloud-native tool designed to retain, analyze, and search data
* Confidentiality: The idea that only authorized users can access specific assets or data
* Confidentiality, integrity, availability (CIA) triad: A model that helps inform how organizations consider risk when setting up systems and security policies

## D
* Detect: A NIST core function related to identifying potential security incidents and improving monitoring capabilities to increase the speed and efficiency of detections

## E
* Encryption: The process of converting data from a readable format to an encoded format
* External threat: Anything outside the organization that has the potential to harm organizational assets

## I
* Identify: A NIST core function related to management of cybersecurity risk and its effect on an organization’s people and assets
* Implement: The fourth step of the NIST RMF that means to implement security and privacy plans for an organization
* Incident response: An organization’s quick attempt to identify an attack, contain the damage, and correct the effects of a security breach
* Integrity: The idea that the data is correct, authentic, and reliable
* Internal threat: A current or former employee, external vendor, or trusted partner who poses a security risk

## L
* Log: A record of events that occur within an organization’s systems

## M
* Metrics: Key technical attributes such as response time, availability, and failure rate, which are used to assess the performance of a software application
*  Monitor: The seventh step of the NIST RMF that means be aware of how systems are operating

## N
* National Institute of Standards and Technology (NIST) Cybersecurity Framework
* (CSF): A voluntary framework that consists of standards, guidelines, and best practices to manage cybersecurity risk
* National Institute of Standards and Technology (NIST) Special Publication (S.P.) 800-53: A unified framework for protecting the security of information systems within the U.S. federal government

## O
* Open Web Application Security Project/Open Worldwide Application Security
* Project (OWASP): A non-profit organization focused on improving software security
* Operating system (OS): The interface between computer hardware and the user

## P
* Playbook: A manual that provides details about any operational action
* Prepare: The first step of the NIST RMF related to activities that are necessary to manage security and privacy risks before a breach occurs
* Protect: A NIST core function used to protect an organization through the implementation of policies, procedures, training, and tools that help mitigate cybersecurity threats

## R
* Ransomware: A malicious attack where threat actors encrypt an organization’s data and demand payment to restore access
* Recover: A NIST core function related to returning affected systems back to normal operation
* Respond: A NIST core function related to making sure that the proper procedures are used to contain, neutralize, and analyze security incidents, and implement improvements to the security process
* Risk: Anything that can impact the confidentiality, integrity, or availability of an asset
* Risk mitigation: The process of having the right procedures and rules in place to quickly reduce the impact of a risk like a breach

## S
* Security audit: A review of an organization's security controls, policies, and procedures against a set of expectations
* Security controls: Safeguards designed to reduce specific security risks
* Security frameworks: Guidelines used for building plans to help mitigate risk and threats to data and privacy
* Security information and event management (SIEM): An application that collects and analyzes log data to monitor critical activities in an organization
* Security orchestration, automation, and response (SOAR): A collection of applications, tools, and workflows that use automation to respond to security events
* Security posture: An organization’s ability to manage its defense of critical assets and data and react to change
* Select: The third step of the NIST RMF that means to choose, customize, and capture documentation of the controls that protect an organization
* Shared responsibility: The idea that all individuals within an organization take an active role in lowering risk and maintaining both physical and virtual security
* SIEM tools: A software platform that collects, analyzes, and correlates security data from various sources across your IT infrastructure that helps identify and respond to security threats in real-time, investigate security incidents, and comply with security regulations
* Social engineering: A manipulation technique that exploits human error to gain private information, access, or valuables
* Splunk Cloud: A cloud-hosted tool used to collect, search, and monitor log data
* Splunk Enterprise: A self-hosted tool used to retain, analyze, and search an organization's log data to provide security information and alerts in real-time

## T
* Threat: Any circumstance or event that can negatively impact assets

## V
* Vulnerability: A weakness that can be exploited by a threat