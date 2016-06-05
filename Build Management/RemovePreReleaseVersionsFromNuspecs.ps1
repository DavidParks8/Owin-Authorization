$configFiles = Get-ChildItem . *.nuspec -rec
foreach ($file in $configFiles)
{
    (Get-Content $file.PSPath) |
    Foreach-Object {$_ -replace "(?<=<version>.*)-.*(?=</version>)", ""} | 
    Set-Content $file.PSPath
}