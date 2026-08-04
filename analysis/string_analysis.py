import re
import subprocess

def extract_indicators(file_path):
    """Extract strings and then find indicators like URLs and IPs."""
    indicators = {
        "urls": [],
        "ips": [],
        "registry_keys": [],
        "all_strings": "" # Store all strings for IOC module
    }
    try:
        # Use the 'strings' command. -n 4 sets the minimum string length.
        result = subprocess.run(['strings', '-n', '4', file_path], capture_output=True, text=True, check=True)
        all_strings = result.stdout
        indicators['all_strings'] = all_strings

        # Regex patterns for common IOCs
        url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\.-?=&%]*'
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        reg_pattern = r'(HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU)\\[-\w\\{}()#$*+?.\[\]]+'

        indicators['urls'] = list(set(re.findall(url_pattern, all_strings)))
        indicators['ips'] = list(set(re.findall(ip_pattern, all_strings)))
        indicators['registry_keys'] = list(set(re.findall(reg_pattern, all_strings, re.IGNORECASE)))

    except FileNotFoundError:
        print("Error: 'strings' command not found. Install binutils.")
    except Exception as e:
        print(f"Error extracting strings: {e}")

    return indicators
