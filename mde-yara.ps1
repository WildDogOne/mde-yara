# Determine the operating system
$os = Get-WmiObject -Class Win32_OperatingSystem

# Set the URL for the YARA executable based on the OS
if ($os.OSArchitecture -eq "64-bit") {
    $yaraUrl = "https://github.com/VirusTotal/yara/releases/download/v4.5.2/yara-v4.5.2-2326-win64.zip"
}
else {
    $yaraUrl = "https://github.com/VirusTotal/yara/releases/download/v4.5.2/yara-v4.5.2-2326-win32.zip"
}

# Define paths
$yaraPath = "C:\temp\yara"
$yaraZipPath = "$yaraPath\yara.zip"
$rulesRepoUrl = "https://github.com/WildDogOne/mde-yara.git"
$rulesPath = "$yaraPath\rules"

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

# Execute YARA with the downloaded rules
$yaraExePath = Get-ChildItem -Path $yaraPath -Filter "yara*.exe" -Recurse | Select-Object -First 1
& $yaraExePath.FullName -r "$rulesPath\*.yar" "C:\path\to\scan"