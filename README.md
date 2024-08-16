# Blue 🧿 Team Cyber Investigation Tricks and Tools 
Welcome to the Blue Team Cyber Investigation Tricks and Tools repository! This collection of resources is designed to aid cybersecurity professionals in defending and securing their networks. Whether you're a seasoned analyst or just getting started, you'll find valuable tools, techniques, and best practices here to enhance your blue team efforts.

<div align="center">

![3](https://i.giphy.com/media/v1.Y2lkPTc5MGI3NjExcDZ4aHNoajhjZzV1a2E5YncyNGdlMzlzemprZnU2MXhoOWpsZ2dodiZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/l0MYuvVSsKz2fQRuo/giphy.gif)
</div> 

## Helpful Online Tools and Websites

### Sandbox Tools 💠

- **[ANY.RUN](https://any.run)**: An interactive online malware sandbox for dynamic analysis of suspicious files.
- **[Cuckoo Sandbox](https://cuckoosandbox.org)**: An open-source automated malware analysis system. ⭐
- **[Hybrid Analysis](https://www.hybrid-analysis.com)**: A free malware analysis service powered by Falcon Sandbox.
- **[Joe Sandbox](https://www.joesandbox.com)**: Advanced analysis of files, URLs, emails, and other types of data.
- **[VirusTotal](https://www.virustotal.com)**: Aggregates many antivirus products and online scan engines to check files and URLs for viruses.

### Email Investigation Tools 🎐

- **[EmailRep](https://emailrep.io)**: A service to query and understand the reputation and associations of an email address.
- **[Hunter.io](https://hunter.io)**: Verifies email addresses and provides related information like domain search and email format.
- **[Have I Been Pwned](https://haveibeenpwned.com)**: Check if an email has been compromised in a data breach.

### IP, Domain, and Reputation Check Tools 🌀

- **[IPVoid](https://www.ipvoid.com)**: Checks IP address reputations with multiple security services.
- **[DomainTools](https://www.domaintools.com)**: Provides detailed domain information including DNS records, Whois, and more.
- **[URLVoid](https://www.urlvoid.com)**: Checks the reputation of websites using multiple blacklist engines and online reputation services.
- **[MXToolbox](https://mxtoolbox.com)**: Provides DNS lookups, blacklist checking, and other useful tools for investigating domains and IPs.
- **[MetaDefender](https://metadefender.opswat.com)**: Scans files, URLs, and IPs with multiple antivirus engines and provides vulnerability assessments.
- **[AbuseIPDB](https://www.abuseipdb.com)**: A database of IP addresses reported for abusive activities, with tools for checking and reporting IPs.
- **[VirusTotal](https://www.virustotal.com)**: In addition to file scanning, VirusTotal also allows for IP, domain, and URL analysis to detect malicious activity. 
- **[ThreatMiner](https://www.threatminer.org)**: A threat intelligence platform that provides context on domains, IPs, and indicators of compromise (IOCs).

### Other Useful Tools 🫧

- **[Shodan](https://www.shodan.io)**: The search engine for Internet-connected devices, useful for finding exposed systems and identifying vulnerabilities.
- **[Censys](https://censys.io)**: Another search engine for finding devices and websites exposed to the internet, including services running on them.
- **[GreyNoise](https://www.greynoise.io)**: Helps distinguish between harmless background noise and targeted attacks by analyzing internet-wide scan traffic.

### Investigating Suspicious Email Addresses

Investigating suspicious email addresses involves several steps, from verifying the email's legitimacy to checking its history and associations. Here's how you can proceed:

1. **Email Verification**: Use tools like [Hunter.io](https://hunter.io) to verify if the email is valid and check for known formats.
2. **Reputation Check**: Use [EmailRep](https://emailrep.io) to check the reputation of the email address and see if it's associated with any malicious activities.
3. **Data Breach Check**: Use [Have I Been Pwned](https://haveibeenpwned.com) to see if the email address has been part of a known data breach.
4. **Domain Analysis**: If the email comes from a specific domain, use [MXToolbox](https://mxtoolbox.com) or [DomainTools](https://www.domaintools.com) to investigate the domain's reputation and history.

These tools and techniques will help you analyze and investigate suspicious elements in your cybersecurity work.

## ☄️ Checklist for Handling a Suspicious Phishing Email and Attached Files ⊹ ࣪ ﹏𓊝﹏𓂁﹏⊹ ࣪ ˖

<div align="center">

![3](https://i.giphy.com/media/v1.Y2lkPTc5MGI3NjExaTEyN3M5dGJzamMxanZrOXpqOTVlNW5penRnaTNiajk5MnoxcmowNiZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/26wAdRgBEvr3A48AE/giphy.gif)
</div> 

### 1. Do Not Interact with the Email
- **Do Not Click**: Avoid clicking any links, downloading attachments, or replying to the email.
- **Do Not Enable**: If the email prompts you to enable macros or content, do not enable them.

### 2. Verify the Sender
- **Check Email Address**: Verify the sender's email address by hovering over it. Look for misspellings or unusual domains.
- **Use Email Verification Tools**: Use tools like [Hunter.io](https://hunter.io) or [EmailRep](https://emailrep.io) to check the legitimacy and reputation of the email address.
- **Inspect Headers**: Analyze the email headers to identify any anomalies in the sender's information.

### 3. Analyze the Email Content
- **Look for Red Flags**: Check for signs of phishing, such as poor grammar, urgent language, or requests for personal information.
- **Compare to Legitimate Emails**: If the email claims to be from a known organization, compare it to previous legitimate emails from that organization.

### 4. Scan the Attached Files
- **Use Online Sandboxes**: Upload the attachment to online sandboxes like [ANY.RUN](https://any.run), [Hybrid Analysis](https://www.hybrid-analysis.com), or [VirusTotal](https://www.virustotal.com) to analyze the file's behavior.
- **Scan with Antivirus**: Run the file through your local antivirus software to detect any known malware.

### 5. Investigate Any URLs
- **Check URL Reputation**: Use tools like [URLVoid](https://www.urlvoid.com) or [VirusTotal](https://www.virustotal.com) to check the reputation of any URLs in the email.
- **Inspect URLs Carefully**: Hover over any links to inspect the full URL. Be cautious of shortened URLs or those with unusual domains.

### 6. Report the Email
- **Internal Reporting**: Follow your organization's procedure for reporting phishing emails. This could involve forwarding the email to your IT or security team.
- **External Reporting**: Report the phishing attempt to relevant authorities or services like [PhishTank](https://www.phishtank.com).

### 7. Quarantine the Email
- **Move to Spam/Junk**: If confirmed as phishing, move the email to your spam or junk folder.
- **Block the Sender**: Block the sender's email address to prevent future phishing attempts from the same source.

### 8. Document the Incident
- **Record Details**: Document all details of the phishing attempt, including the sender's address, email content, attached files, and any analysis results.
- **Share Findings**: Share your findings with your team or community to help others recognize similar threats.

### 9. Monitor for Impact
- **Check for Signs of Compromise**: After handling the phishing attempt, monitor your systems for any unusual activity that may indicate a compromise.
- **Update Security Measures**: If necessary, update your security measures, such as email filters, to prevent similar attacks in the future.

### 10. Educate and Train
- **Awareness Training**: Educate others in your organization about phishing threats and how to recognize and respond to them.
- **Simulate Phishing Attacks**: Conduct phishing simulations to test and improve your organization's readiness to handle such threats.

