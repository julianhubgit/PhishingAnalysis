# Phishing Analysis

<h2>Description</h2>

I will demonstrate how to carry out in depth phishing analysis. I will be identifying malicious techniques using the MITRE ATT&amp;CK framework, using Atomic Red Team tests to conduct attack simulations and creating alerting and detection rules from the attack tests

<h2>Languages and Utilities Used</h2>

- MITRE ATT&CK framework
- Cyber Kill Chain
- AtomicTest
- Powershell
- Windows Event Viewer

All cyber attacks follow a fairly standard process, which is explained quite well by the Unified Cyber Kill chain.

Below is an image of the Cyber Kill chain.


<img src="https://i.imgur.com/H5AHriM.png" alt="Unified Cyber Kill chain"/>

MITRE ATT&CK framework is a collection of tactics, techniques, and procedures that have been seen to be implemented by real threat actors. The framework provides a navigator tool where these TTPs can be investigated. 

<h2>Scenario</h2>

In this scenario it is suspected that the supposed attacker used the **MITRE ATT&CK technique T1566.001: Spearphishing with an attachment. **Let's recreate the attack emulation performed by the supposed attacker and then look for the artefacts created.

<h2>Task with in-depth breakdown</h2>

**AtomicTest** can be used to recreate the attack emulation performed by the supposed attacker and then look for the artefacts created.

The **Invoke-AtomicTest **function can be used to run an atomic test on the system where Atomic Red Team (Local) is installed, or on a remote machine through a **PowerShell** Remoting session (Remote).


The command Get-Help Invoke-Atomictest will give details on the commands within the AtomicTest tool/
-ShowDetails: Shows the details of each test included in the Atomic. *Invoke-AtomicTest T1566.001 -ShowDetails* shown below:

<img src="https://i.imgur.com/zR22Qz1.png" alt="AtomicTest"/>

A breakdown of the attack shows that it is executing a command in powershell, downloading two phishing attachments .xlsm and .txt and saving them in TEMP folder and then a cleanup command is removing the phishing files.

Screenshot below shows parameters and explains what they do:

<img src="https://i.imgur.com/tdBwdhZ.png" alt="Attack breakdown within Powershell using AtomicTest"/>

Before running the emulation, we should ensure that all required resources are in place to conduct it successfully. 

To verify this, we can add the flag **-Checkprereq** to our command. The command should look something like this: **Invoke-AtomicTest T1566.001 -TestNumbers 1 -CheckPrereq.**

Now that we have executed the T1566.001 Atomic, we can look for log entries that point us to this emulated attack. For this purpose, we will use the Windows Event Logs. This machine comes with Sysmon installed. System Monitor (Sysmon) provides us with detailed information about process creation, network connections, and changes to file creation time.

To make it easier for us to pick up the events created for this emulation, we will first start with cleaning up files from the previous test by running the command **Invoke-AtomicTest T1566.001 -TestNumbers 1 -cleanup.**
Now, we will clear the Sysmon event log:
- Open up the Event Viewer by clicking the icon in the taskbar, or searching for it in the Start Menu.
- Navigate to Applications and Services => Microsoft => Windows => Sysmon => Operational on the left-hand side of the screen.
- Right-click Operational on the left-hand side of the screen and click Clear Log. Click Clear when the popup shows.


Now that we have cleaned up the files and the sysmon logs, let us run the emulation again by issuing the command: **Invoke-AtomicTest T1566.001 -TestNumbers 1.**

Next, go to the Event Viewer and right-click on the Operational log on the left-hand side of the screen and then click on Refresh. There should be new events related to the emulated attack. Now sort the table on the Date and Time column to order the events chronologically (oldest first). The first two events of the list are tests that Atomic executes for every emulation. We are interested in 2 events that detail the attack:

- First, a process was created for PowerShell to execute the following command: **"powershell.exe" & {$url = 'http://localhost/PhishingAttachment.xlsm' Invoke-WebRequest -Uri $url -OutFile $env:TEMP\PhishingAttachment.xlsm}.**

- Then, a file was created with the name **PhishingAttachment.xlsm.**

Let's clean up the artefacts from our spearphishing emulation. Enter the command **Invoke-AtomicTest T1566.001-1 -cleanup.**

Now that we know which artefacts were created during this **spearphishing** emulation, we can use them to create custom alerting rules. In the next section, we will explore this topic further.

In the previous paragraph, we found multiple indicators of compromise through the Sysmon event log. We can use this information to create detection rules to include in our **EDR, SIEM, IDS, etc.** These tools offer functionalities that allow us to import custom detection rules. There are several detection rule formats, including **Yara, Sigma, Snort, and more.** Let's look at how we can implement the artefacts related to T1566.001 to create a custom Sigma rule.

Two events contained possible indicators of compromise. Let's focus on the event that contained the Invoke-WebRequest command line:
"powershell.exe" & {$url = 'http://localhost/PhishingAttachment.xlsm' Invoke-WebRequest -Uri $url -OutFile $env:TEMP\PhishingAttachment.xlsm}"

We can use multiple parts of this artefact to include in our custom Sigma rule.
**Invoke-WebRequest:** It is not common for this command to run from a script behind the scenes.

**$url = 'http://localhost/PhishingAttachment.xlsm':** Attackers often use a specific malicious domain to host their payloads. Including the malicious URL in the Sigma rule could help us detect that specific URL.

**PhishingAttachment.xlsm:** This is the malicious payload downloaded and saved on our system. We can include its name in the Sigma rule as well.

