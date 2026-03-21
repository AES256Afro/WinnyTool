"""
Security Resources Hub - Curated links to security tools, channels, and communities.
"""

import webbrowser


def get_security_resources():
    """Return a dict of security resource categories, each containing a list of resources."""
    return {
        "Security Tools": [
            {"name": "Shields Up! (GRC)", "url": "https://www.grc.com/shieldsup", "description": "Online port scanner and firewall tester", "category": "Security Tools"},
            {"name": "VirusTotal", "url": "https://www.virustotal.com", "description": "Multi-engine file/URL scanner", "category": "Security Tools"},
            {"name": "Have I Been Pwned", "url": "https://haveibeenpwned.com", "description": "Check if your email was in a data breach", "category": "Security Tools"},
            {"name": "Shodan", "url": "https://www.shodan.io", "description": "Internet-connected device search engine", "category": "Security Tools"},
            {"name": "CyberChef", "url": "https://gchq.github.io/CyberChef", "description": "Data encoding/decoding Swiss army knife", "category": "Security Tools"},
            {"name": "Wireshark", "url": "https://www.wireshark.org", "description": "Network protocol analyzer", "category": "Security Tools"},
            {"name": "Nmap", "url": "https://nmap.org", "description": "Network discovery and security auditing", "category": "Security Tools"},
            {"name": "Sysinternals Suite", "url": "https://learn.microsoft.com/en-us/sysinternals", "description": "Windows system utilities by Mark Russinovich", "category": "Security Tools"},
            {"name": "Autoruns", "url": "https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns", "description": "Comprehensive startup program manager", "category": "Security Tools"},
            {"name": "Process Explorer", "url": "https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer", "description": "Advanced task manager with VirusTotal integration", "category": "Security Tools"},
        ],
        "YouTube Channels": [
            {"name": "NetworkChuck", "url": "https://www.youtube.com/@NetworkChuck", "description": "Networking and cybersecurity tutorials", "category": "YouTube Channels"},
            {"name": "John Hammond", "url": "https://www.youtube.com/@_JohnHammond", "description": "CTF walkthroughs and malware analysis", "category": "YouTube Channels"},
            {"name": "The Cyber Mentor", "url": "https://www.youtube.com/@TCMSecurityAcademy", "description": "Ethical hacking and penetration testing", "category": "YouTube Channels"},
            {"name": "David Bombal", "url": "https://www.youtube.com/@davidbombal", "description": "Networking and security deep dives", "category": "YouTube Channels"},
            {"name": "LiveOverflow", "url": "https://www.youtube.com/@LiveOverflow", "description": "Binary exploitation and hacking", "category": "YouTube Channels"},
            {"name": "IppSec", "url": "https://www.youtube.com/@ippsec", "description": "HackTheBox walkthroughs", "category": "YouTube Channels"},
            {"name": "13Cubed", "url": "https://www.youtube.com/@13Cubed", "description": "Digital forensics and incident response", "category": "YouTube Channels"},
            {"name": "Black Hills InfoSec", "url": "https://www.youtube.com/@BlackHillsInformationSecurity", "description": "Enterprise security and threat hunting", "category": "YouTube Channels"},
        ],
        "CVE Aggregates & Databases": [
            {"name": "NVD (NIST)", "url": "https://nvd.nist.gov", "description": "National Vulnerability Database", "category": "CVE Aggregates & Databases"},
            {"name": "MITRE CVE", "url": "https://cve.mitre.org", "description": "CVE numbering authority and registry", "category": "CVE Aggregates & Databases"},
            {"name": "CISA KEV", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "description": "Known exploited vulnerabilities catalog", "category": "CVE Aggregates & Databases"},
            {"name": "Microsoft Security Update Guide", "url": "https://msrc.microsoft.com/update-guide", "description": "Microsoft vulnerability advisories and patches", "category": "CVE Aggregates & Databases"},
            {"name": "CVE Details", "url": "https://www.cvedetails.com", "description": "CVE security vulnerability data and statistics", "category": "CVE Aggregates & Databases"},
            {"name": "Exploit-DB", "url": "https://www.exploit-db.com", "description": "Exploit database and proof-of-concept archive", "category": "CVE Aggregates & Databases"},
            {"name": "VulnDB", "url": "https://vuldb.com", "description": "Vulnerability intelligence and tracking", "category": "CVE Aggregates & Databases"},
        ],
        "Current Threats & News": [
            {"name": "CISA Alerts", "url": "https://www.cisa.gov/news-events/alerts", "description": "US-CERT security alerts and advisories", "category": "Current Threats & News"},
            {"name": "Krebs on Security", "url": "https://krebsonsecurity.com", "description": "Investigative cybersecurity journalism", "category": "Current Threats & News"},
            {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com", "description": "Security news, tutorials, and support", "category": "Current Threats & News"},
            {"name": "The Hacker News", "url": "https://thehackernews.com", "description": "Cybersecurity news and analysis", "category": "Current Threats & News"},
            {"name": "Dark Reading", "url": "https://www.darkreading.com", "description": "Enterprise security news and research", "category": "Current Threats & News"},
            {"name": "SecurityWeek", "url": "https://www.securityweek.com", "description": "Cybersecurity news and conference coverage", "category": "Current Threats & News"},
            {"name": "Ars Technica Security", "url": "https://arstechnica.com/security", "description": "In-depth security and technology reporting", "category": "Current Threats & News"},
        ],
        "Reddit Communities": [
            {"name": "r/cybersecurity", "url": "https://www.reddit.com/r/cybersecurity", "description": "General cybersecurity discussion", "category": "Reddit Communities"},
            {"name": "r/netsec", "url": "https://www.reddit.com/r/netsec", "description": "Network security research and news", "category": "Reddit Communities"},
            {"name": "r/AskNetsec", "url": "https://www.reddit.com/r/AskNetsec", "description": "Security questions and answers", "category": "Reddit Communities"},
            {"name": "r/sysadmin", "url": "https://www.reddit.com/r/sysadmin", "description": "System administration discussion", "category": "Reddit Communities"},
            {"name": "r/homelab", "url": "https://www.reddit.com/r/homelab", "description": "Home lab setups and projects", "category": "Reddit Communities"},
            {"name": "r/privacy", "url": "https://www.reddit.com/r/privacy", "description": "Privacy-focused discussions", "category": "Reddit Communities"},
            {"name": "r/malware", "url": "https://www.reddit.com/r/malware", "description": "Malware analysis and research", "category": "Reddit Communities"},
        ],
        "Community & Slack": [
            {"name": "Mac Admins Slack", "url": "https://www.macadmins.org", "description": "Mac administration community (Slack workspace)", "category": "Community & Slack"},
            {"name": "DFIR Discord", "url": "https://www.digitalforensics.com", "description": "Digital forensics and incident response community", "category": "Community & Slack"},
            {"name": "Blue Team Labs Online", "url": "https://blueteamlabs.online", "description": "Defensive security training and challenges", "category": "Community & Slack"},
            {"name": "TryHackMe", "url": "https://tryhackme.com", "description": "Hands-on cybersecurity training platform", "category": "Community & Slack"},
            {"name": "HackTheBox", "url": "https://www.hackthebox.com", "description": "Penetration testing labs and challenges", "category": "Community & Slack"},
        ],
    }


def open_resource(url):
    """Open a resource URL in the default browser."""
    webbrowser.open(url)
