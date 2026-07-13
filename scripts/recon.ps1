# penguin launcher (Windows)
$root = (Get-Item $PSScriptRoot).Parent.FullName
Set-Location $root
python -m penguin @args
