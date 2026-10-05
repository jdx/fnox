# The release build action uses Git Bash, whose Perl lacks OpenSSL modules.
# Resolve the runner's native interpreter before entering that shell.
$ErrorActionPreference = 'Stop'
$perl = (Get-Command perl.exe -ErrorAction Stop).Source
& $perl -MLocale::Maketext::Simple -MIPC::Cmd -e 1
if ($LASTEXITCODE -ne 0) {
    throw "Native Perl is missing modules required by vendored OpenSSL"
}
"OPENSSL_SRC_PERL=$perl" | Out-File -FilePath $env:GITHUB_ENV -Encoding utf8 -Append
