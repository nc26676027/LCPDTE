[CmdletBinding()]
param(
    [string]$SourcePath = (Join-Path $PSScriptRoot '..\upstream\fhe-simd-alu\src\pke\include\scheme\ckksrns\z-fhe-constants.h'),
    [switch]$DigestOnly
)

$ErrorActionPreference = 'Stop'
$resolvedSource = (Resolve-Path -LiteralPath $SourcePath).Path
$source = Get-Content -Raw -LiteralPath $resolvedSource

$vectorPattern = '(?s)const std::vector<BigComplex> coeff_exp_16_big_complex_46 = \{(?<body>.*?)\r?\n\};'
$vectors = [regex]::Matches($source, $vectorPattern)
if ($vectors.Count -ne 1) {
    throw "expected exactly one coeff_exp_16_big_complex_46 vector, found $($vectors.Count)"
}

$entryPattern = 'BigComplex\(BigFixedPoint\(BigInteger\("(?<real>\d+)"\), 128, (?<realNegative>true|false)\),\s*BigFixedPoint\(BigInteger\("(?<imaginary>\d+)"\), 128, (?<imaginaryNegative>true|false)\)\)'
$entries = [regex]::Matches($vectors[0].Groups['body'].Value, $entryPattern)
if ($entries.Count -ne 47) {
    throw "expected 47 degree-46 coefficients, found $($entries.Count)"
}

$lines = [System.Collections.Generic.List[string]]::new()
for ($index = 0; $index -lt $entries.Count; $index++) {
    $entry = $entries[$index]
    $real = $entry.Groups['real'].Value
    $imaginary = $entry.Groups['imaginary'].Value
    if ($entry.Groups['realNegative'].Value -eq 'true' -and $real -ne '0') {
        $real = '-' + $real
    }
    if ($entry.Groups['imaginaryNegative'].Value -eq 'true' -and $imaginary -ne '0') {
        $imaginary = '-' + $imaginary
    }
    $lines.Add(('exp' + [char]9 + $index + [char]9 + $real + [char]9 + $imaginary))
}

$canonical = [string]::Join("`n", $lines) + "`n"
$sha256 = [System.Security.Cryptography.SHA256]::Create()
try {
    $digestBytes = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($canonical))
}
finally {
    $sha256.Dispose()
}
$digest = [Convert]::ToHexString($digestBytes).ToLowerInvariant()

if ($DigestOnly) {
    Write-Output $digest
}
else {
    Write-Output $lines
}
