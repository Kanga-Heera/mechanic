param(
    [string]$OutFile = "D:\sigma-research\mechanic\data\phase3_run_results_run2_wide.json",
    [string]$PyExe = "D:\sigma-research\venv\Scripts\python.exe",
    [string]$Script = "D:\sigma-research\mechanic\scripts\run_phase3_acceptance.py",
    [int]$MaxTotal = 28,
    [int]$StallSeconds = 180,
    [int]$SleepBetween = 10
)

$env:GROQ_API_KEY = [System.Environment]::GetEnvironmentVariable("GROQ_API_KEY", "User")
$env:MECHANIC_RSIGMA_BIN = "D:\sigma-research\tools\rsigma\rsigma.exe"

function Get-CompletedCount {
    if (Test-Path $OutFile) {
        try {
            return (Get-Content $OutFile -Raw | ConvertFrom-Json).summary.total
        } catch {
            return $script:LastKnownTotal
        }
    }
    return 0
}

$script:LastKnownTotal = Get-CompletedCount
$attempt = 0

while ((Get-CompletedCount) -lt $MaxTotal) {
    $attempt++
    $done = Get-CompletedCount
    Write-Output "=== [$(Get-Date -Format 'HH:mm:ss')] Attempt $attempt - completed so far: $done/$MaxTotal ==="

    $stdout = "D:\sigma-research\mechanic\data\phase3_supervisor_stdout_$attempt.log"
    $stderr = "D:\sigma-research\mechanic\data\phase3_supervisor_stderr_$attempt.log"
    $proc = Start-Process -FilePath $PyExe -ArgumentList @($Script, "--sleep", "$SleepBetween", "--out", $OutFile, "--resume") `
        -PassThru -NoNewWindow -RedirectStandardOutput $stdout -RedirectStandardError $stderr

    $lastWrite = if (Test-Path $OutFile) { (Get-Item $OutFile).LastWriteTime } else { Get-Date }
    $lastStdoutWrite = Get-Date

    while (-not $proc.HasExited) {
        Start-Sleep -Seconds 15
        $currentWrite = if (Test-Path $OutFile) { (Get-Item $OutFile).LastWriteTime } else { $lastWrite }
        $currentStdoutWrite = if (Test-Path $stdout) { (Get-Item $stdout).LastWriteTime } else { $lastStdoutWrite }
        if ($currentWrite -gt $lastWrite) { $lastWrite = $currentWrite }
        if ($currentStdoutWrite -gt $lastStdoutWrite) { $lastStdoutWrite = $currentStdoutWrite }

        $idleSeconds = ((Get-Date) - $lastStdoutWrite).TotalSeconds
        if ($idleSeconds -gt $StallSeconds) {
            Write-Output "  [$(Get-Date -Format 'HH:mm:ss')] No stdout progress for $([int]$idleSeconds)s - treating as stalled, killing PID $($proc.Id) and its children."
            try {
                Get-CimInstance Win32_Process -Filter "ParentProcessId=$($proc.Id)" -ErrorAction SilentlyContinue |
                    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
            } catch {}
            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
            break
        }
    }

    if ($proc.HasExited -and $proc.ExitCode -eq 0) {
        Write-Output "  [$(Get-Date -Format 'HH:mm:ss')] Attempt $attempt exited cleanly (code 0)."
    }
    $script:LastKnownTotal = Get-CompletedCount
}

Write-Output "=== DONE: $(Get-CompletedCount)/$MaxTotal rules completed after $attempt attempt(s) ==="
