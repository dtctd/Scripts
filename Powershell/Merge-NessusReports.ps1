<#

.SYNOPSIS
This powershell script merges Nessus scans.

.DESCRIPTION
This powershell script downloads all Nessus scans in the folder specified, merge the downloaded scans and uploads a consolidated report to the root of the Nessus host.

.EXAMPLE
./Merge-NessusReport.ps1 -server 192.168.1.1 -folder Test

.NOTES
The server argument defaults to 127.0.0.1 and is optional.

.LINK
https://github.com/dtctd/Scripts/blob/master/Powershell/Merge-NessusReports.ps1

#>
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
    if((Test-Path -Path "$TargetDir\output\") -eq $True) {
        Debug "Output folder allready exists"
    }
    else {
        New-Item -ItemType Directory -Force -Path $TargetDir\Output\| out-null
    }
    if((Test-Path -Path "$TargetDir\Processed\") -eq $True ) {
        Debug "Processed folder allready exists"
    }
    else {
        New-Item -ItemType Directory -Force -Path $TargetDir\Processed\| out-null
    }
    
    
    if((Test-Path -Path "$TargetDir\Output\consolidated.nessus") -eq $True) {
        Write-host($(Get-Date -Format HH:mm) + " - Removing old merge file...") -ForegroundColor Yellow
        Remove-Item -Path "$TargetDir\Output\consolidated.nessus" -Force
    }

    $First = Get-ChildItem $TargetDir -Filter *.nessus | Select -First 1
    $Last = Get-ChildItem $TargetDir -Filter *.nessus | Select -Last 1
    Debug "Firstfile is $First and the last file is $last"
    
    
    Get-ChildItem $TargetDir -Filter *.nessus | %{

        If($_.Name -ne $First.Name){
            $SkipLines = (Select-String -Path $_.FullName -SimpleMatch "<Report name=" | select -expand LineNumber)
        }
        else {
            $SkipLines = 0
        }
        
        If($_.Name -ne $Last.Name){
        $RemoveLines = 2
        }
        else {
        $RemoveLines = 0
        }

        Debug "$SkipLines lines skipped for $_.name length of file is $EndLine"
        
        StreamEdit $_.FullName $SkipLines $RemoveLines
        Move-Item $_.FullName $TargetDir\Processed -Force
    }
}

function CountLines($InputFile){
    $count = 0
    $reader = New-Object System.IO.StreamReader ($InputFile)
    while ($reader.ReadLine() -ne $null){$count++}
    $reader.Close()
    return [int]$count
}

function StreamEdit($InputFile,[int]$SkipLines,[int]$RemoveLines) {
    $TotalLines = CountLines($InputFile)
   
    $LinesToProcessCount = ($TotalLines - $RemoveLines)
    Debug "The total is $TotalLines and the lines to process is $LinesToProcessCount for $InputFile"
    $Curcount = 0
    $ins = New-Object System.IO.StreamReader ($InputFile)
    $outs = New-Object System.IO.StreamWriter -ArgumentList ([IO.File]::Open(($TargetDir + "\Output\consolidated.nessus"),"Append")) 
    try {
        # skip the first N lines
        for( $s = 1; $s -le $SkipLines; $s++ ) {
            $ins.ReadLine() > $null
            
        }
        $Curcount = $Curcount + $SkipLines
        while( $Curcount -ne $LinesToProcessCount -and $Curcount -lt $TotalLines) {
            #Debug "current: $curcount, to process: $LinesToProcessCount"
            $outs.WriteLine( $ins.ReadLine() )
            $Curcount++
        }
        Debug "Written $Curcount lines."
    }
    
    finally {
        Debug "Finished with $InputFile"
        $outs.Close()
        $ins.Close()
    }
}

function Rename-Report($ReportName) {
    $InputFile = "$TargetDir\Output\consolidated.nessus"
    $stringToReplace = '\<Report name=\".*\"\sxmlns\:cm=\"http\:\/\/www\.nessus\.org\/cm\">'
    $replaceWith = '<Report name="' + $ReportName + ' ' + (get-date -format dd/MM/yyyy) +'" xmlns:cm="http://www.nessus.org/cm">'
    
    try {
    $reader = [System.IO.StreamReader] $InputFile
    $data = $reader.ReadToEnd()
    $reader.close()
    }
    
    finally {
        if ($reader -ne $null) {
            $reader.dispose()
        }
    }

    $data = $data -replace $stringToReplace, $replaceWith

    try {
        $writer = [System.IO.StreamWriter] $InputFile
        $writer.write($data)
        $writer.close()
    }

    finally {
        if ($writer -ne $null) {
            $writer.dispose()
        }
    }
}

function Debug($DebugMessage){
    if ($debug -eq 1) {
        write-host $DebugMessage
    }
        
}

Function Import-Report {
    Import-Module -Name Posh-Nessus
    Write-host($(Get-Date -Format HH:mm) + " - Starting import.")
    $session = New-NessusSession -ComputerName $Server -Credentials $Cred
    Import-NessusScan -SessionId $session.SessionId -File "$TargetDir\Output\consolidated.nessus" #> $null
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
    $ReportName = "Consolidated $Folder"
    Export-Reports
    Merge-Reports
    Rename-Report $ReportName
    Import-Report
    Write-host($(Get-Date -Format HH:mm) + " - Main finished") -ForegroundColor Green
}

Main
