/*
    Cryptocurrency Miner Detection Rules
    Detects crypto miners, mining pools, and related activities
*/

rule Miner_Crypto_APIs
{
    meta:
        description = "Detects cryptographic APIs used by miners"
        severity = "high"
        threat_level = "critical"
        malware_type = "cryptominer"
        
    strings:
        $crypto1 = "CryptHashData" nocase
        $crypto2 = "CryptAcquireContext" nocase
        $crypto3 = "CryptCreateHash" nocase
        $crypto4 = "sha256" nocase
        $crypto5 = "scrypt" nocase
        $crypto6 = "keccak" nocase
        
    condition:
        3 of them
}

rule Miner_Pool_Connections
{
    meta:
        description = "Detects connections to known mining pools"
        severity = "critical"
        
    strings:
        $pool1 = "stratum" nocase wide ascii
        $pool2 = "mining" nocase wide ascii
        $pool3 = "pool." nocase
        $pool4 = "xmr." nocase
        $pool5 = "eth." nocase
        $pool6 = "btc." nocase
        $pool7 = "cryptonight" nocase
        $pool8 = "nicehash" nocase wide ascii
        
    condition:
        2 of them
}

rule Miner_Wallet_Addresses
{
    meta:
        description = "Detects cryptocurrency wallet address patterns"
        severity = "high"
        
    strings:
        $btc = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/
        $eth = /0x[a-fA-F0-9]{40}/
        $xmr = /4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}/
        
    condition:
        any of them
}

rule Miner_CPU_GPU_Usage
{
    meta:
        description = "Detects CPU and GPU optimization for mining"
        severity = "medium"
        
    strings:
        $cpu1 = "num_threads" nocase wide ascii
        $cpu2 = "max_cpu" nocase wide ascii
        $cpu3 = "cpu_affinity" nocase
        $cpu4 = "SetThreadAffinityMask" nocase
        $gpu1 = "CUDA" nocase
        $gpu2 = "OpenCL" nocase
        $gpu3 = "nvidia" nocase wide ascii
        
    condition:
        2 of them
}

rule Miner_XMRig
{
    meta:
        description = "Detects XMRig miner specifically"
        severity = "critical"
        
    strings:
        $xmrig1 = "xmrig" nocase wide ascii
        $xmrig2 = "donate-level" nocase wide ascii
        $xmrig3 = "randomx" nocase wide ascii
        $xmrig4 = "argon2" nocase wide ascii
        $xmrig5 = "rx/wow" nocase
        $xmrig6 = "cryptonight" nocase
        
    condition:
        3 of them
}

rule Miner_Process_Hiding
{
    meta:
        description = "Detects techniques to hide mining processes"
        severity = "high"
        
    strings:
        $hide1 = "NtQuerySystemInformation" nocase
        $hide2 = "HideProcess" nocase
        $hide3 = "SetWindowLong" nocase
        $hide4 = "SW_HIDE" nocase
        $hide5 = "taskkill" nocase wide ascii
        $hide6 = "taskmgr" nocase wide ascii
        
    condition:
        3 of them
}

rule Miner_Configuration
{
    meta:
        description = "Detects miner configuration patterns"
        severity = "medium"
        
    strings:
        $config1 = "config.json" nocase wide ascii
        $config2 = "pools" nocase wide ascii
        $config3 = "algo" nocase wide ascii
        $config4 = "worker" nocase wide ascii
        $config5 = "pass" nocase wide ascii
        $config6 = "url" nocase wide ascii
        
    condition:
        3 of them
}

rule Miner_Coinhive
{
    meta:
        description = "Detects Coinhive and browser-based miners"
        severity = "high"
        
    strings:
        $ch1 = "coinhive" nocase wide ascii
        $ch2 = "cryptoloot" nocase wide ascii
        $ch3 = "minero" nocase wide ascii
        $ch4 = "webminer" nocase wide ascii
        $ch5 = "CoinHive.Anonymous" nocase
        $ch6 = "jsecoin" nocase wide ascii
        
    condition:
        any of them
}

rule Miner_WebAssembly
{
    meta:
        description = "Detects WebAssembly-based miners"
        severity = "medium"
        
    strings:
        $wasm1 = "WebAssembly" nocase
        $wasm2 = ".wasm" nocase
        $wasm3 = "instantiate" nocase
        $wasm4 = "memory" nocase wide ascii
        $wasm5 = "Module" nocase
        
    condition:
        3 of them
}

