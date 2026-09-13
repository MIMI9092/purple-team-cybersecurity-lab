@{
    LabName             = 'CBI-Purple-Team-Lab'
    EnableLiveExecution = $false
    VmStartDelaySeconds = 10
    AttackOnlyExcludedVirtualMachines = @('Splunk', 'Shuffle')

    Tools = @{
        VmRunPath = 'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe'
        SshPath   = 'ssh.exe'
        ScpPath   = 'scp.exe'
    }

    VirtualMachines = @{
        GNS3 = @{
            # Set the local GNS3 VMX path in lab.local.psd1.
            VmxPath = ''
            # Started automatically by the GNS3 desktop application.
            RequiredForPB05 = $false
        }
        OPNsense = @{
            # Set the local OPNsense VMX path in lab.local.psd1.
            VmxPath = ''
            RequiredForPB05 = $true
        }
        Dvwa = @{
            # Set the local DMZ-DVWA VMX path in lab.local.psd1.
            VmxPath = ''
            RequiredForPB05 = $true
        }
        ActiveDirectory = @{
            # Set the local AD-DC01 VMX path in lab.local.psd1.
            VmxPath = ''
            RequiredForPB05 = $true
        }
        Windows10 = @{
            # Set the local WIN10-CLIENT01 VMX path in lab.local.psd1.
            VmxPath = ''
            RequiredForPB05 = $true
        }
        Kali = @{
            # Add the real Kali .vmx path to lab.local.psd1.
            VmxPath = ''
            RequiredForPB05 = $true
        }
        Splunk = @{
            # Set the local Splunk VMX path in lab.local.psd1.
            VmxPath = ''
            RequiredForPB05 = $false
        }
        Shuffle = @{
            # Set the local Shuffle VMX path in lab.local.psd1.
            VmxPath = ''
            RequiredForPB05 = $false
        }
    }

    Hosts = @{
        Kali = @{
            Name    = 'Kali'
            Address = '192.168.111.144'
            SshPort = 22
            SshUser = 'kali'
        }
        OPNsense = @{
            Name    = 'OPNsense'
            Address = '10.10.70.1'
            WebPort = 443
        }
        DomainController = @{
            Name     = 'AD-DC01'
            Address  = '10.10.30.10'
            LdapPort = 389
        }
        Windows10 = @{
            Name      = 'WIN10-CLIENT01'
            Address   = '10.10.30.20'
            WinRmPort = 5985
        }
        Splunk = @{
            Name           = 'Splunk'
            Address        = '10.10.50.10'
            WebPort        = 8000
            ManagementPort = 8089
        }
        Shuffle = @{
            Name         = 'Shuffle'
            Address      = '10.10.50.30'
            FrontendPort = 3001
            BackendPort  = 5001
        }
        Dvwa = @{
            Name            = 'DVWA'
            Address         = '10.10.60.10'
            WebPort         = 80
            ExternalAddress = '192.168.111.128'
            ExternalPort    = 8080
        }
    }

    Pivots = @{
        DvwaSocksPort       = 1080
        WindowsSocksPort    = 1081
        PersistenceSocksPort = 1082
        ChiselServerPort    = 443
    }

    PB05 = @{
        AttackTransport      = 'EvilWinRMOverDvwaSocks'
        Domain               = 'LAB'
        UserName             = 'svc_web'
        UserSid              = 'S-1-5-21-722403993-16450863-2166090910-1106'
        RunValueName         = 'PFA-Lab-Tunnel'
        RunKeyPath           = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
        PersistenceScript    = 'C:\Users\svc_web\AppData\Local\PFA-Lab\pfa-tunnel.ps1'
        ChiselPath           = 'C:\Users\svc_web\Documents\chisel.exe'
        CallbackAddress      = '192.168.111.144'
        CallbackPort         = 443
        ReverseSocksPort     = 1082
        Marker               = 'PFA_PERSISTENCE_C2_01'
        KaliChiselServerPath = '/usr/bin/chisel'
        KaliStaticChiselPath = '/home/kali/pfa-evidence/phase3-pivot/chisel-static'
        StaticChiselSha256   = '8fc08cb354379cbdfa735eb2cb6a9a045b25fe37967f28b1917625d7cdc052a3'
        KaliWindowsChiselPath = '/home/kali/pfa-evidence/phase3-pivot/chisel.exe'
        WindowsChiselSha256  = '0D16DF569A45A5512783C1146FEB6D3A1C7233FC44046E04F4714529FAEB25AA'
        HistoricalScriptSha256 = '8345B32B60DF079E2F17779EA98D7BBA016B194EB5BB0572F182FFFD579D8AC2'
        DvwaProxyConfig      = '/home/kali/pfa-evidence/phase3-pivot/proxychains-dmz.conf'
        WindowsProxyConfig   = '/home/kali/pfa-evidence/phase3-pivot/proxychains-win10.conf'
        PersistenceProxyConfig = '/home/kali/pfa-evidence/phase6-persistence/proxychains-persistence.conf'
    }

    PrivilegeEscalation = @{
        Domain            = 'LAB'
        UserName          = 'svc_web'
        UserSid           = 'S-1-5-21-722403993-16450863-2166090910-1106'
        ServiceName       = 'PFA-Lab-Updater'
        ServiceExecutable = 'C:\Program Files\PFA-Lab\PFA-Lab-Updater.exe'
        VulnerableScript  = 'C:\ProgramData\PFA-Lab\PrivilegeEscalation\PFA-Lab-Updater.ps1'
        ProofArtifact     = 'C:\ProgramData\PFA-Lab\PrivilegeEscalation\system-proof.json'
        EventSource       = 'PFA-Lab-PrivilegeEscalation'
        Marker            = 'PFA_SERVICE_PRIVESC_01'
    }
}
