import re

def extract_iocs(all_strings):
    """A more aggressive IOC extraction from all raw strings."""
    iocs = {
        "ip_addresses": [],
        "domains": [],
        "emails": [],
        "mutexes": [],
    }

    # Extract IPs
    iocs['ip_addresses'] = list(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', all_strings)))

    # Extract Domains (a simple, not production-ready regex)
    domain_pattern = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'
    iocs['domains'] = list(set(re.findall(domain_pattern, all_strings)))

    # Extract Emails
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    iocs['emails'] = list(set(re.findall(email_pattern, all_strings)))

    # Extract potential Mutex names (often preceded by "CreateMutex" or similar)
    mutex_pattern = r'CreateMutex[A-Za-z0-9_]*"([^"]+)"'
    iocs['mutexes'] = list(set(re.findall(mutex_pattern, all_strings)))

    return iocs
