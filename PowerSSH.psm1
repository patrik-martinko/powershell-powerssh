Function Set-PowerSSH {
    If (-Not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Start-Process -FilePath (Get-Process -Id $PID).Path -Verb RunAs -ArgumentList "-Command Set-PowerSSH"
    } Else {
        Set-Alias -Name ssh -Value Invoke-SshCommand
        If (-Not (Test-Path -PathType Leaf -Path $Profile)) {
            New-Item -ItemType File -Path $Profile
        }
        $Content = "Set-Alias -Name ssh -Value Invoke-SshCommand"
        If (-Not (Get-Content -Path $Profile | Select-String -SimpleMatch $Content)) {
            Add-Content -Path $Profile -Value "`r`n$Content"
        }
        $Capability = (Get-WindowsCapability -Online | Where-Object -Property Name -Like 'OpenSSH.Client*')
        If ($Capability.State -Eq 'NotPresent') {
            Add-WindowsCapability -Online -Name $Capability.Name
            Set-Service ssh-agent -StartupType Manual
            Restart-Computer
        } Else {
            Set-Service ssh-agent -StartupType Manual
        }
    }
}
Function Invoke-SshCommand {
    $Identity = Ssh-Add.exe -l 2>&1
    If (($Identity -Is [Management.Automation.ErrorRecord]) -And ($Identity.Exception.Message -Match 'Error connecting to agent')) {
        Ssh-Agent.exe
        $Identity = Ssh-Add.exe -l 2>&1
    }
    If (($Identity -Is [String]) -And ($Identity -Match 'The agent has no identities')) {
        Ssh-Keygen.exe -f "$Home/.ssh/id_ed25519" -t ed25519 -a 100
        If (Get-SshBackwardCompatibilityMode) {
            Ssh-Keygen.exe -f "$Home/.ssh/id_rsa" -t rsa -b 4096 -a 100
            Ssh-Add.exe "$Home/.ssh/id_ed25519" "$Home/.ssh/id_rsa"
            Remove-Item -Path "$Home/.ssh/id_rsa"
        } Else {
            Ssh-Add.exe "$Home/.ssh/id_ed25519"
        }
        Remove-Item -Path "$Home/.ssh/id_ed25519"
    }
    For ($i = 0; $i -Lt $Args.Count; $i++) {
        If ((-Not $ParameterPreviousWithHyphen) -And (-Not $Args[$i].StartsWith('-'))) {
            $Hosts = @() + (Get-SshInstalledHost)
            If ($Hosts -NotContains $Args[$i]) {
                # Installation
                $KeyPublic = Get-SshPublicKey
                If ((Ssh.exe $Args[0..$i] "mkdir ~/.ssh 2>/dev/null; touch ~/.ssh/authorized_keys; grep -q -F '$KeyPublic' ~/.ssh/authorized_keys || echo '$KeyPublic' >> ~/.ssh/authorized_keys; grep -F '$KeyPublic' ~/.ssh/authorized_keys")) {
                    If (Get-SshBackwardCompatibilityMode) {
                        $KeyRsaPublic = Get-SshPublicRsaKey
                        Ssh.exe $Args[0..$i] "grep -q -F '$KeyRsaPublic' ~/.ssh/authorized_keys || echo '$KeyRsaPublic' >> ~/.ssh/authorized_keys"
                    }
                    $Hosts += $Args[$i]
                    [Environment]::SetEnvironmentVariable('PowerSSH/Hosts', $Hosts -Join ';', 'User')
                }
            }
            Break
        }
        $ParameterPreviousWithHyphen = $Args[$i].StartsWith('-')
    }
    If ($MyInvocation.InvocationName -Eq 'Invoke-SshCommand') {
        Ssh.exe $Args
    } Else {
        &($MyInvocation.InvocationName + '.exe') $Args
    }
}
Function Get-SshBackwardCompatibilityMode {
    [Convert]::ToBoolean([Environment]::GetEnvironmentVariable('PowerSSH/BackwardCompatibilityMode', 'User'))
}
Function Set-SshBackwardCompatibilityMode {
    Param(
        [Parameter(Mandatory = $True, Position = 0)][Boolean] $Value
    )
    [Environment]::SetEnvironmentVariable('PowerSSH/BackwardCompatibilityMode', $Value, 'User')
}
Function Get-SshPublicKey {
    Get-Content -Path "$Home/.ssh/id_ed25519.pub"
}
Function Get-SshPublicRsaKey {
    Get-Content -Path "$Home/.ssh/id_rsa.pub"
}
Function Get-SshInstalledHost {
    Param(
        [Parameter(Mandatory = $False, Position = 0)] $Hostname
    )
    [Environment]::GetEnvironmentVariable('PowerSSH/Hosts', 'User') -Split ';' |
    Where-Object { If ($Hostname) { $_ -Eq $Hostname } Else { $_ } }
}
Function Remove-SshInstalledHost {
    Param(
        [Parameter(Mandatory = $False, Position = 0)] $Hostname
    )
    If ($Hostname) {
        $Hosts = Get-SshInstalledHost | Where-Object { $_ -Ne $Hostname }
        Get-Content -Path "$Home/.ssh/known_hosts" | Select-String -Pattern $Hostname -NotMatch | Set-Content -Path "$Home/.ssh/known_hosts"
    } Else {
        $Hosts = @()
        Remove-Item -Path "$Home/.ssh/known_hosts"
    }
    [Environment]::SetEnvironmentVariable('PowerSSH/Hosts', $Hosts -Join ';', 'User')
    ForEach ($Hostname in $Hosts) {
        Remove-SshInstalledPublicKey -Hostname $Hostname
    }
}
Function Get-SshInstalledPublicKey {
    Param(
        [Parameter(Mandatory = $True, Position = 0)] $Hostname,
        [Parameter(Mandatory = $False, Position = 1)][Switch] $Others
    )
    If ($Others) {
        Ssh $Hostname 'cat ~/.ssh/authorized_keys'
    } Else {
        Ssh $Hostname "grep '$(Get-SshPublicKey)' ~/.ssh/authorized_keys"
        If (Get-SshBackwardCompatibilityMode) {
            Ssh $Hostname "grep '$(Get-SshPublicRsaKey)' ~/.ssh/authorized_keys"
        }
    }
}
Function Remove-SshInstalledPublicKey {
    Param(
        [Parameter(Mandatory = $True, Position = 0)] $Hostname,
        [Parameter(Mandatory = $False, Position = 1)][Switch] $Others
    )
    If ($Others) {
        Ssh $Hostname 'rm ~/.ssh/authorized_keys'
    } Else {
        Ssh $Hostname "grep -v '$(Get-SshPublicKey)' ~/.ssh/authorized_keys > ~/.ssh/tmp; mv ~/.ssh/tmp ~/.ssh/authorized_keys"
        If (Get-SshBackwardCompatibilityMode) {
            Ssh $Hostname "grep -v '$(Get-SshPublicRsaKey)' ~/.ssh/authorized_keys > ~/.ssh/tmp; mv ~/.ssh/tmp ~/.ssh/authorized_keys"
        }
    }
}
Function Clear-SshKeys {
    Param(
        [Parameter(Mandatory = $False, Position = 1)][Switch] $Others
    )
    Remove-SshInstalledHost -Others $Others
    Ssh-Add.exe -D
    Remove-Item -Path "$Home/.ssh/id_ed25519.pub" -ErrorAction Ignore
    Remove-Item -Path "$Home/.ssh/id_rsa.pub" -ErrorAction Ignore
}