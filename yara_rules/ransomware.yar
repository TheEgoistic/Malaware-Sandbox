/*
    Ransomware Detection Rules
    Detects common ransomware behaviors, strings, and patterns
*/

rule Ransomware_Encryption_APIs
{
    meta:
        description = "Detects APIs commonly used by ransomware for file encryption"
        author = "Malware Sandbox"
        date = "2024-01"
        severity = "high"
        threat_level = "critical"
        malware_type = "ransomware"
        
    strings:
        $api1 = "CryptEncrypt" nocase
        $api2 = "CryptDecrypt" nocase
        $api3 = "CryptGenKey" nocase
        $api4 = "CryptAcquireContext" nocase
        $api5 = "CryptDeriveKey" nocase
        $api6 = "CryptGenRandom" nocase
        
    condition:
        3 of them
}

rule Ransomware_File_Operations
{
    meta:
        description = "Detects file enumeration and modification patterns"
        severity = "high"
        
    strings:
        $find1 = "FindFirstFile" nocase
        $find2 = "FindNextFile" nocase
        $delete = "DeleteFile" nocase
        $move = "MoveFile" nocase
        $create = "CreateFile" nocase
        $write = "WriteFile" nocase
        
    condition:
        3 of them and $delete
}

rule Ransomware_Shadow_Copy_Deletion
{
    meta:
        description = "Detects Volume Shadow Copy deletion commands"
        severity = "critical"
        
    strings:
        $vss1 = "vssadmin.exe" nocase wide ascii
        $vss2 = "Delete Shadows" nocase wide ascii
        $vss3 = "wmic.exe" nocase wide ascii
        $vss4 = "shadowcopy" nocase wide ascii
        $vss5 = "Win32_ShadowCopy" nocase wide ascii
        
    condition:
        any of them
}

rule Ransomware_Backup_Deletion
{
    meta:
        description = "Detects commands to delete system backups"
        severity = "critical"
        
    strings:
        $bcd1 = "bcdedit" nocase wide ascii
        $bcd2 = "bootstatuspolicy" nocase
        $bcd3 = "recoveryenabled" nocase
        $wbadmin = "wbadmin" nocase wide ascii
        $backup = "delete catalog" nocase wide ascii
        $sql = "BACKUP DATABASE" nocase
        
    condition:
        2 of them
}

rule Ransomware_Ransom_Note
{
    meta:
        description = "Detects strings commonly found in ransomware notes"
        severity = "high"
        
    strings:
        $note1 = "ransom" nocase wide ascii
        $note2 = "decrypt" nocase wide ascii
        $note3 = "encrypted" nocase wide ascii
        $note4 = "bitcoin" nocase wide ascii
        $note5 = "payment" nocase wide ascii
        $note6 = "how to decrypt" nocase wide ascii
        $note7 = "your files" nocase wide ascii
        $note8 = "contact us" nocase wide ascii
        
    condition:
        3 of them
}

rule Ransomware_Extensions
{
    meta:
        description = "Detects common ransomware file extensions"
        severity = "medium"
        
    strings:
        $ext1 = ".encrypted" nocase wide ascii
        $ext2 = ".locked" nocase wide ascii
        $ext3 = ".crypt" nocase wide ascii
        $ext4 = ".enc" nocase wide ascii
        $ext5 = ".aaa" nocase
        $ext6 = ".zzz" nocase
        $ext7 = ".xxx" nocase
        $ext8 = ".ttt" nocase
        
    condition:
        any of them
}

rule Ransomware_Registry_Disable
{
    meta:
        description = "Detects registry modifications to disable security features"
        severity = "high"
        
    strings:
        $reg1 = "DisableTaskMgr" nocase wide ascii
        $reg2 = "DisableRegistryTools" nocase wide ascii
        $reg3 = "DisableCMD" nocase wide ascii
        $reg4 = "NoRun" nocase
        $reg5 = "NoClose" nocase
        $reg6 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server" nocase
        
    condition:
        2 of them
}

rule Ransomware_Network_Discovery
{
    meta:
        description = "Detects network share discovery for ransomware spreading"
        severity = "medium"
        
    strings:
        $net1 = "NetShareEnum" nocase
        $net2 = "NetServerEnum" nocase
        $net3 = "WNetEnumResource" nocase
        $net4 = "\\\\" wide ascii
        $net5 = "SMB" nocase
        $net6 = "\\ADMIN$" nocase
        $net7 = "\\C$" nocase
        
    condition:
        3 of them
}

