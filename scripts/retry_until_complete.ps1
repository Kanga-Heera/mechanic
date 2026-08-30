param(
    [string]$OutFile = "D:\sigma-research\mechanic\data\phase3_run_results_run2_wide.json",
    [string]$PyExe = "D:\sigma-research\venv\Scripts\python.exe",
    [string]$Script = "D:\sigma-research\mechanic\scripts\run_phase3_acceptance.py",
    [string]$ClearScript = "D:\sigma-research\mechanic\scripts\_clear_run_errors.py",
    [int]$MaxTotal = 28,
    [int]$SleepBetween = 30,
    [int]$LlmTimeout = 150,
    [int]$MaxCycles = 30
)

$env:GROQ_API_KEY = [System.Environment]::GetEnvironmentVariable("GROQ_API_KEY", "User")
$env:MECHANIC_RSIGMA_BIN = "D:\sigma-research\tools\rsigma\rsigma.exe"

function Get-RealCount {
    if (-not (Test-Path $OutFile)) { return 0 }
    $json = Get-Content $OutFile -Raw | ConvertFrom-Json
    return ($json.results | Where-Object { $_.outcome -ne "RUN_ERROR" }).Count
}

$cycle = 0
while ((Get-RealCount) -lt $MaxTotal -and $cycle -lt $MaxCycles) {
    $cycle++
    if (Test-Path $OutFile) { & $PyExe $ClearScript $OutFile }
    $real = Get-RealCount
    Write-Output "=== [$(Get-Date -Format 'HH:mm:ss')] Cycle $cycle - real outcomes so far: $real/$MaxTotal ==="
    & $PyExe $Script --sleep $SleepBetween --llm-timeout $LlmTimeout --out $OutFile --resume
}

if (Test-Path $OutFile) { & $PyExe $ClearScript $OutFile }
Write-Output "=== FINAL: $(Get-RealCount)/$MaxTotal real outcomes after $cycle cycle(s) ==="
