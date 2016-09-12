#Requires -Version 3.0
param (
    [string]$Server = "127.0.0.1",
    [Parameter(Mandatory=$true)][string]$Folder
 )

Function Install-NessusPOSH() {
    # Make sure the module is not loaded
    Remove-Module Posh-Nessus -ErrorAction SilentlyContinue
    # Download latest version
    $webclient = New-Object System.Net.WebClient
    $url = "https://github.com/tenable/Posh-Nessus/archive/master.zip"
    Write-host($(Get-Date -Format HH:mm) + " - Downloading latest version of Posh-Nessus from $url") -ForegroundColor Cyan
    $file = "$($env:TEMP)\Posh-Nessus.zip"
    $webclient.DownloadFile($url,$file)

    Write-host($(Get-Date -Format HH:mm) + " - File saved to $file") -ForegroundColor Green
    # Unblock and decompress
    Unblock-File -Path $file
    $targetondisk = "$([System.Environment]::GetFolderPath('MyDocuments'))\WindowsPowerShell\Modules"
    New-Item -ItemType Directory -Force -Path $targetondisk | out-null
    $shell_app=new-object -com shell.application
    $zip_file = $shell_app.namespace($file)
    Write-host($(Get-Date -Format HH:mm) + " - Uncompressing the Zip file to $($targetondisk)") -ForegroundColor Cyan
    $destination = $shell_app.namespace($targetondisk)
    $destination.Copyhere($zip_file.items(), 0x10)
    # Rename and import
    Write-host($(Get-Date -Format HH:mm) + " - Renaming folder") -ForegroundColor Cyan
    Rename-Item -Path ($targetondisk+"\Posh-Nessus-master") -NewName "Posh-Nessus" -Force
    Write-host($(Get-Date -Format HH:mm) + " - Module has been installed") -ForegroundColor Green
    Import-Module -Name Posh-Nessus
    Get-Command -Module Posh-Nessus
}

Function Export-Reports() {
    Write-host($(Get-Date -Format HH:mm) + " - Starting export")
    Import-Module -Name Posh-Nessus
    $session = New-NessusSession -ComputerName $Server -Credentials $Cred

    $folder = Get-NessusFolder -SessionId $session.SessionId | Where-Object {$_.name -eq $Folder}

    $scans = Get-NessusScan -SessionId $session.SessionId -FolderId $folder[0].FolderId | Where-Object {$_.Status -eq "completed" }

    $scans  | ForEach-Object{ 
        $scan = $_ 
        $name = $scan.Name -replace "[\\\/]", "_"
        Write-host($(Get-Date -Format HH:mm) + " - Exporting $name")
        $histories = Show-NessusScanHistory -SessionId $session.SessionId -ScanId $scan.ScanId | Where-Object {$_.Status -eq "completed"} 
        if ($histories) {
            $hist = $histories[0] 
            Export-NessusScan -SessionId $session.SessionId -ScanId $scan.ScanId  -Format "nessus" -OutFile "$TargetDir\$name.nessus" -HistoryID $hist.HistoryId
        }            
    }
    Write-host($(Get-Date -Format HH:mm) + " - Exports finished.") -ForegroundColor Green
}

Function Merge-Reports() {
    Write-host($(Get-Date -Format HH:mm) + " - Starting merge, please be patient it takes a while...")
    if(Test-Path -Path "$TargetDir\consolidated.nessus") {
        Write-host($(Get-Date -Format HH:mm) + " - Removing old merge file...") -ForegroundColor Yellow
        Remove-Item -Path "$TargetDir\consolidated.nessus" -Force
    }
    $Reports = Get-ChildItem $TargetDir -force| Where-Object {$_.Extension -eq ".nessus"} | select Name, FullName
    $MainPath = $Reports[0].FullName
    [xml]$MainReport = Get-Content -Path $MainPath -Raw

    foreach ($Report in $Reports) {      
        $Reportpath = $Report.FullName
        if ( $Reportpath -ne $MainPath) {
             Write-host($(Get-Date -Format HH:mm) + " - Merging " + ($Report.Name))
            [xml]$ReportToAdd = Get-Content -Path $Reportpath -Raw
            $ReportHostsToAdd = $ReportToAdd.NessusClientData_v2.Report.SelectNodes("ReportHost")
            foreach($ReportHost in $ReportHostsToAdd) {
                $Node = $MainReport.ImportNode($ReportHost, $true)
                $MainReport.NessusClientData_v2.Report.AppendChild($Node) > $null
            }
            Remove-Item $Reportpath -Force       
        }
    }
    $MainReport.Save("$TargetDir\consolidated.nessus")
    Remove-Item $MainPath -Force 
    Write-host($(Get-Date -Format HH:mm) + " - Merging finished") -ForegroundColor Green
}

Function Import-Report {
    Import-Module -Name Posh-Nessus
    Write-host($(Get-Date -Format HH:mm) + " - Starting import.")
    $session = New-NessusSession -ComputerName $Server -Credentials $Cred
    $FileName = '<Report name="Consolidated ' + (get-date -format dd/MM/yyyy) + '"'
    (Get-Content -path "$TargetDir\consolidated.nessus" -ReadCount 0) -replace '<Report name=".*?"',$FileName | Set-Content $TargetDir\consolidated.nessus
    Import-NessusScan -SessionId $session.SessionId -File "$TargetDir\consolidated.nessus" > $null
    Write-host($(Get-Date -Format HH:mm) + " - Import finished.") -ForegroundColor Green
}

Function Main() {
    Write-host($(Get-Date -Format HH:mm) + " - Starting main")
    if (Get-Module -ListAvailable -Name "Posh-Nessus") {
        Write-host($(Get-Date -Format HH:mm) + " - Posh-Nessus module installed continuing...")
    }
    else {
        Write-host($(Get-Date -Format HH:mm) + " - Posh-Nessus module does not exist, installing...") -ForegroundColor Yellow
        Install-NessusPOSH
    }

    $Path = [Environment]::GetFolderPath("MyDocuments")
    $TargetDir = "$Path\Nessus"
    if(!(Test-Path -Path $TargetDir)) {
        Write-host($(Get-Date -Format HH:mm) + " - Creating $TargetDir") -ForegroundColor Yellow
        New-Item -ItemType directory -Path $TargetDir
    }

    $Cred = Get-Credential
    Export-Reports
    Merge-Reports
    Import-Report
    Write-host($(Get-Date -Format HH:mm) + " - Main finished") -ForegroundColor Green
}

Main
