$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root
python -m penguin @args
