# Verifica se o script está sendo executado com privilégios de administrador
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Você precisa executar este script como administrador. Por favor, execute o PowerShell como administrador e tente novamente."
    exit
}

#definir permição de execução de scripts para o usuario em questao. 
set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force -Scope CurrentUser

#muda a rede de Publica para privada.

Set-NetConnectionProfile -InterfaceAlias "*" -NetworkCategory Private


# Define o nome de usuário a ser procurado (neste caso, "Helper" ou "HELPER")
$targetUser = "Helper", "HELPER", "helper" 

# Define a nova senha
$newPassword = "helpertec1@"

# Loop através dos nomes de usuário alvo
foreach ($user in $targetUser) {
    # Verifica se o usuário existe
    $userExists = Get-LocalUser | Where-Object { $_.Name -eq $user }

    if ($userExists) {
        # Se o usuário existir, informa que foi encontrado
        Write-Host "O usuário $user foi encontrado."

        # Define a nova senha para o usuário
        Set-LocalUser -Name $user -Password (ConvertTo-SecureString $newPassword -AsPlainText -Force)

        # Confirmação da alteração de senha
        Write-Host "A senha do usuário $user foi alterada para $newPassword."

        # Configurar o autologon para o usuário
        reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "AutoAdminLogon" /t REG_SZ /d "1" /f
        reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "DefaultUserName" /t REG_SZ /d "$user" /f
        reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "DefaultPassword" /t REG_SZ /d "$newPassword" /f

        Write-Host "O autologon foi configurado para o usuário $user."
    } else {
        # Se o usuário não for encontrado, informa que não foi encontrado
        Write-Host "O usuário $user não foi encontrado."
    }
}


Start-Service -Name "WinRM"

# Definir o tipo de inicialização como Automático
Set-Service -Name "WinRM" -StartupType Automatic


# Habilita o serviço WinRM
Write-Host "Habilitando o serviço WinRM..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value 1 -Force
Enable-PSRemoting -Force

# Configura o ouvinte HTTP do WinRM
Write-Host "Configurando o ouvinte HTTP do WinRM..."
winrm create winrm/config/Listener?Address=*+Transport=HTTP

# Abre a porta 5985 no firewall para permitir o tráfego do WinRM
Write-Host "Configurando regra de firewall para permitir o tráfego do WinRM (HTTP)..."
netsh advfirewall firewall add rule name="WinRM-HTTP" dir=in action=allow protocol=TCP localport=5985

# Abre a porta 5986 no firewall para permitir o tráfego do WinRM (HTTPS)
Write-Host "Configurando regra de firewall para permitir o tráfego do WinRM (HTTPS)..."
netsh advfirewall firewall add rule name="WinRM-HTTPS" dir=in action=allow protocol=TCP localport=5986

# Configura o WinRM para permitir credenciais de rede não autenticadas
Write-Host "Configurando o WinRM para permitir credenciais de rede não autenticadas..."
winrm set winrm/config/service/auth '@{Basic="true"}'
winrm set winrm/config/service '@{AllowUnencrypted="true"}'

# Habilita a autenticação básica
Write-Host "Habilitando a autenticação básica do WinRM..."
winrm set winrm/config/client/auth '@{Basic="true"}'

# Habilita a autenticação CredSSP
Write-Host "Habilitando a autenticação CredSSP do WinRM..."
winrm set winrm/config/client/auth '@{CredSSP="true"}'

Write-Host "Configuração do WinRM concluída com sucesso."

#############################

# Verifique se o recurso OpenSSH já está instalado
$openSSHInstalled = Get-WindowsCapability -Online | Where-Object { $_.Name -like 'OpenSSH*' }

if ($openSSHInstalled) {
    Write-Output "OpenSSH já está instalado."
} else {
    # Instale o OpenSSH Client e Server
    Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
    Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0

    # Inicie o serviço sshd
    Start-Service sshd

    # Opcional, mas recomendado: Defina o serviço para iniciar automaticamente
    Set-Service -Name sshd -StartupType 'Automatic'

    # Verifique e configure a regra de firewall
    $firewallRule = Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue

    if (-not $firewallRule) {
        Write-Output "A regra de firewall 'OpenSSH-Server-In-TCP' não existe, criando..."
        New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
    } else {
        Write-Output "A regra de firewall 'OpenSSH-Server-In-TCP' já foi criada e existe."
    }
}


exit
