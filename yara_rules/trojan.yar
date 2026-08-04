/*
    Trojan Detection Rules
    Detects various types of trojans, backdoors, and RATs
*/

rule Trojan_Persistence
{
    meta:
        description = "Detects common trojan persistence mechanisms"
        severity = "high"
        threat_level = "critical"
        malware_type = "trojan"
        
    strings:
        $persist1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" nocase wide ascii
        $persist2 = "CurrentVersion\\RunOnce" nocase wide ascii
        $persist3 = "SchTasks" nocase wide ascii
        $persist4 = "Startup" nocase wide ascii
        $persist5 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" nocase
        $persist6 = "Services\\" nocase wide ascii
        
    condition:
        2 of them
}

rule Trojan_C2_Communication
{
    meta:
        description = "Detects command and control communication patterns"
        severity = "critical"
        
    strings:
        $c2_1 = "InternetOpen" nocase
        $c2_2 = "InternetConnect" nocase
        $c2_3 = "HttpOpenRequest" nocase
        $c2_4 = "HttpSendRequest" nocase
        $c2_5 = "InternetReadFile" nocase
        $c2_6 = "URLDownloadToFile" nocase
        $c2_7 = "WinHttpOpen" nocase
        
    condition:
        3 of them
}

rule Trojan_Backdoor
{
    meta:
        description = "Detects backdoor functionality"
        severity = "critical"
        
    strings:
        $bd1 = "CreateProcess" nocase
        $bd2 = "cmd.exe" nocase wide ascii
        $bd3 = "powershell" nocase wide ascii
        $bd4 = "recv" nocase
        $bd5 = "socket" nocase
        $bd6 = "connect" nocase
        $bd7 = "bind" nocase
        $bd8 = "listen" nocase
        
    condition:
        3 of them
}

rule Trojan_Keylogger
{
    meta:
        description = "Detects keylogging functionality"
        severity = "high"
        
    strings:
        $key1 = "SetWindowsHookEx" nocase
        $key2 = "GetAsyncKeyState" nocase
        $key3 = "GetKeyState" nocase
        $key4 = "GetForegroundWindow" nocase
        $key5 = "GetWindowText" nocase
        $key6 = "WM_KEYDOWN" nocase
        $key7 = "VK_" nocase
        
    condition:
        3 of them
}

rule Trojan_Process_Injection
{
    meta:
        description = "Detects process injection techniques"
        severity = "high"
        
    strings:
        $inj1 = "VirtualAllocEx" nocase
        $inj2 = "WriteProcessMemory" nocase
        $inj3 = "CreateRemoteThread" nocase
        $inj4 = "OpenProcess" nocase
        $inj5 = "NtCreateThreadEx" nocase
        $inj6 = "QueueUserAPC" nocase
        $inj7 = "SetThreadContext" nocase
        
    condition:
        2 of them
}

rule Trojan_Anti_Analysis
{
    meta:
        description = "Detects anti-analysis and anti-debugging techniques"
        severity = "medium"
        
    strings:
        $anti1 = "IsDebuggerPresent" nocase
        $anti2 = "CheckRemoteDebuggerPresent" nocase
        $anti3 = "NtQueryInformationProcess" nocase
        $anti4 = "OutputDebugString" nocase
        $anti5 = "GetTickCount" nocase
        $anti6 = "QueryPerformanceCounter" nocase
        $anti7 = "rdtsc" nocase
        
    condition:
        2 of them
}

rule Trojan_Data_Exfiltration
{
    meta:
        description = "Detects data theft and exfiltration patterns"
        severity = "high"
        
    strings:
        $exfil1 = "FTP" nocase wide ascii
        $exfil2 = "smtp" nocase
        $exfil3 = "POST" nocase
        $exfil4 = "credentials" nocase wide ascii
        $exfil5 = "password" nocase wide ascii
        $exfil6 = "browser" nocase wide ascii
        $exfil7 = "cookie" nocase wide ascii
        
    condition:
        3 of them
}

rule Trojan_Downloader
{
    meta:
        description = "Detects downloader trojans"
        severity = "high"
        
    strings:
        $dl1 = "URLDownloadToFile" nocase
        $dl2 = "WinHttpOpen" nocase
        $dl3 = "WinHttpConnect" nocase
        $dl4 = "WinHttpOpenRequest" nocase
        $dl5 = "WinHttpSendRequest" nocase
        $dl6 = "WinHttpReceiveResponse" nocase
        $dl7 = "http://" nocase ascii
        $dl8 = "https://" nocase ascii
        
    condition:
        (2 of ($dl*)) and any of ($dl7, $dl8)
}

