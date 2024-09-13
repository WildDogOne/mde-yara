param (
    [string]$searchPath = "C:\"
)

# Variables
# Define paths
$yaraPath = "C:\temp\yara"
$yaraZipPath = "$yaraPath\yara.zip"
$rulesRepoUrl = "https://github.com/WildDogOne/mde-yara.git"
$rulesPath = "$yaraPath\rules"
$yaraResults = "$yaraPath\yara_results.txt"

# Remove the YARA directory if it exists
if (Test-Path -Path $yaraPath) {
    Remove-Item -Path $yaraPath -Recurse -Force
}

# Determine the operating system
$os = Get-WmiObject -Class Win32_OperatingSystem

# Set the URL for the YARA executable based on the OS
if ($os.OSArchitecture -eq "64-bit") {
    $yaraUrl = "https://github.com/VirusTotal/yara/releases/download/v4.5.2/yara-v4.5.2-2326-win64.zip"
    $yaraExePath = "$yaraPath/yara64.exe"
}
else {
    $yaraUrl = "https://github.com/VirusTotal/yara/releases/download/v4.5.2/yara-v4.5.2-2326-win32.zip"
    $yaraExePath = "$yaraPath/yara32.exe"
}

# Create directories if they don't exist
if (-Not (Test-Path -Path $yaraPath)) {
    New-Item -ItemType Directory -Path $yaraPath
}

# Download the YARA executable ZIP file
Invoke-WebRequest -Uri $yaraUrl -OutFile $yaraZipPath

# Extract the YARA executable ZIP file
Expand-Archive -Path $yaraZipPath -DestinationPath $yaraPath

# Download the YARA rules repository
if (-Not (Test-Path -Path $rulesPath)) {
    New-Item -ItemType Directory -Path $rulesPath
}
git clone $rulesRepoUrl $rulesPath

# Get all YARA Rules in path
$yaraRules = Get-ChildItem -Path $rulesPath -Recurse -Include *.yar

# Convert $yaraRules to space-separated string
$yaraRules = $yaraRules -join " "

"YARA scan started" | Out-File -FilePath $yaraResults

# Execute YARA with the downloaded rules
& $yaraExePath -s -r $yaraRules "$searchPath" | Out-File -FilePath $yaraResults -Append

"YARA scan complete" | Out-File -FilePath $yaraResults -Append