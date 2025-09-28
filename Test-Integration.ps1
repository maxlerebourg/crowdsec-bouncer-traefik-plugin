#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Runs integration tests for the CrowdSec Bouncer Traefik Plugin

.DESCRIPTION
    This script starts the Docker Compose services, waits for them to be ready,
    runs the Pester integration tests covering different bouncer modes and scenarios,
    and then cleans up the services.

.PARAMETER SkipDockerCleanup
    Skip stopping Docker services after tests complete (useful for debugging)

.PARAMETER SkipWait
    Skip waiting for services to be ready (assumes they're already running)

.PARAMETER TestPath
    Path to the Pester test files or directory (defaults to ./tests/ to run all test files)


.PARAMETER HttpTimeoutSeconds
    HTTP timeout for bouncer testing (defaults to 30)

.EXAMPLE
    ./Test-Integration.ps1
    Runs the full integration test suite

.EXAMPLE
    ./Test-Integration.ps1 -TestPath "./tests/mode_stream.Tests.ps1" -HttpTimeoutSeconds 60
    Tests only stream mode with 60 second timeout

.EXAMPLE
    ./Test-Integration.ps1 -SkipDockerCleanup
    Runs tests but leaves Docker services running for debugging
#>

[CmdletBinding()]
param(
    [switch]$SkipDockerCleanup,
    [switch]$SkipWait,
    [string]$TestPath = "./tests/",
    [int]$HttpTimeoutSeconds = 30
)

$ErrorActionPreference = "Stop"

# Colors for output
$Colors = @{
    Info = "Cyan"
    Success = "Green"
    Warning = "Yellow"
    Error = "Red"
}

function Write-Step {
    param([string]$Message, [string]$Color = "Cyan")
    Write-Host "🔄 $Message" -ForegroundColor $Color
}

function Write-Success {
    param([string]$Message)
    Write-Host "✅ $Message" -ForegroundColor $Colors.Success
}

function Write-Warning {
    param([string]$Message)
    Write-Host "⚠️  $Message" -ForegroundColor $Colors.Warning
}

function Write-Error {
    param([string]$Message)
    Write-Host "❌ $Message" -ForegroundColor $Colors.Error
}

function Test-ServiceHealth {
    param(
        [string]$Url,
        [string]$ServiceName,
        [int]$TimeoutSeconds = 120,
        [int]$RetryIntervalSeconds = 3,
        [int]$ExpectedStatusCode = 200
    )
    
    Write-Step "Waiting for $ServiceName to be ready..."
    $elapsed = 0
    
    do {
        try {
            $response = Invoke-WebRequest -Uri $Url -Method Get -TimeoutSec 10 -UseBasicParsing -ErrorAction SilentlyContinue
            if ($response.StatusCode -eq $ExpectedStatusCode) {
                Write-Success "$ServiceName is ready! (Status: $($response.StatusCode))"
                return $true
            }
        }
        catch {
            # Service not ready yet, continue waiting
        }
        
        Start-Sleep $RetryIntervalSeconds
        $elapsed += $RetryIntervalSeconds
        
        if ($elapsed % 15 -eq 0) {
            Write-Host "  Still waiting for $ServiceName... ($elapsed/$TimeoutSeconds seconds)" -ForegroundColor Gray
        }
        
    } while ($elapsed -lt $TimeoutSeconds)
    
    Write-Error "$ServiceName failed to become ready within $TimeoutSeconds seconds"
    return $false
}

function Test-CrowdSecAPI {
    param(
        [string]$ApiKey,
        [int]$TimeoutSeconds = 60
    )
    
    Write-Step "Testing CrowdSec LAPI connection..."
    $elapsed = 0
    
    do {
        try {
            $headers = @{ "X-Api-Key" = $ApiKey }
            $response = Invoke-RestMethod -Uri "http://localhost:8081/v1/decisions?limit=1" -Headers $headers -TimeoutSec 5
            Write-Success "CrowdSec LAPI is responding!"
            return $true
        }
        catch {
            Write-Host "  LAPI test failed: $($_.Exception.Message)" -ForegroundColor Yellow
            Write-Host "  Status Code: $($_.Exception.Response.StatusCode)" -ForegroundColor Yellow
            Start-Sleep 3
            $elapsed += 3
        }
        
    } while ($elapsed -lt $TimeoutSeconds)
    
    Write-Error "CrowdSec LAPI failed to respond within $TimeoutSeconds seconds"
    return $false
}

# Main execution
try {
    Write-Host ""
    Write-Host "🚀 CrowdSec Bouncer Traefik Plugin Integration Test Runner" -ForegroundColor $Colors.Info
    Write-Host "=========================================================" -ForegroundColor $Colors.Info
    Write-Host "Test Path: $TestPath" -ForegroundColor $Colors.Info
    Write-Host "HTTP Timeout: $HttpTimeoutSeconds seconds" -ForegroundColor $Colors.Info
    Write-Host ""

    # Check if Pester is available
    Write-Step "Checking Pester availability..."
    try {
        Import-Module Pester -Force -ErrorAction Stop
        $pesterVersion = (Get-Module Pester).Version
        if ($pesterVersion.Major -lt 5) {
            Write-Warning "Pester version $pesterVersion detected. Upgrading to v5+..."
            Install-Module -Name Pester -Force -Scope CurrentUser -SkipPublisherCheck
            Import-Module Pester -Force
        }
        Write-Success "Pester $pesterVersion is available"
    }
    catch {
        Write-Error "Pester module not found. Installing Pester..."
        try {
            Install-Module -Name Pester -Force -Scope CurrentUser -SkipPublisherCheck
            Import-Module Pester -Force
            Write-Success "Pester installed and imported successfully"
        }
        catch {
            Write-Error "Failed to install Pester: $($_.Exception.Message)"
            exit 1
        }
    }

    # Ensure we are using Linux containers
    Write-Step "Ensuring Linux containers are enabled..."
    try {
        $dockerInfo = docker info --format "{{.OSType}}" 2>$null
        if ($dockerInfo -eq "linux") {
            Write-Success "Docker is using Linux containers"
        } else {
            Write-Warning "Docker may not be using Linux containers. Some tests may fail."
        }
    }
    catch {
        Write-Warning "Could not verify Docker container type"
    }

    # Check if Docker Compose is available
    Write-Step "Checking Docker Compose availability..."
    try {
        $dockerComposeVersion = docker compose version 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Docker Compose is available"
        } else {
            throw "Docker Compose not found"
        }
    }
    catch {
        Write-Error "Docker Compose is not available. Please install Docker Desktop or Docker Compose."
        exit 1
    }

    # Set environment variables for testing
    $env:HTTP_TIMEOUT_SECONDS = $HttpTimeoutSeconds
    $env:BOUNCER_API_KEY = "40796d93c2958f9e58345514e67740e5"

    # Clean up any existing services
    Write-Step "Cleaning up any existing services..."
    docker compose -f docker-compose.test.yml down -v --remove-orphans 2>$null

    # Start Docker services
    Write-Step "Starting Docker Compose services for testing..."
    try {
        docker compose -f docker-compose.test.yml up -d
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to start Docker services"
        }
        Write-Success "Docker services started successfully"
    }
    catch {
        Write-Error "Failed to start Docker services: $($_.Exception.Message)"
        exit 1
    }

    if (-not $SkipWait) {
        # Wait for services to be ready
        Write-Step "Waiting for services to become ready..."
        
        $servicesReady = @(
            (Test-ServiceHealth -Url "http://localhost:8080/api/rawdata" -ServiceName "Traefik API" -TimeoutSeconds 60),
            (Test-ServiceHealth -Url "http://localhost:8000/whoami" -ServiceName "Whoami test service" -TimeoutSeconds 60),
            (Test-CrowdSecAPI -ApiKey $env:BOUNCER_API_KEY -TimeoutSeconds 90)
        )
        
        if ($servicesReady -contains $false) {
            Write-Error "One or more services failed to start properly"
            if (-not $SkipDockerCleanup) {
                Write-Step "Cleaning up Docker services..."
                docker compose -f docker-compose.test.yml down -v
            }
            exit 1
        }
        
        Write-Success "All services are ready!"
        
        # Give CrowdSec a moment to fully initialize
        Write-Step "Allowing CrowdSec to complete initialization..."
        Start-Sleep 10
        
    } else {
        Write-Warning "Skipping service readiness check (assuming services are already running)"
    }

    # Run Pester tests
    Write-Step "Running Pester integration tests..."
    Write-Host ""
    
    if (-not (Test-Path $TestPath)) {
        Write-Error "Test path not found: $TestPath"
        exit 1
    }

    try {
        $pesterConfig = New-PesterConfiguration
        $pesterConfig.Run.Path = $TestPath
        $pesterConfig.Output.Verbosity = 'Detailed'
        $pesterConfig.Run.Exit = $false
        $pesterConfig.Run.PassThru = $true
        $pesterConfig.TestResult.Enabled = $true
        $pesterConfig.TestResult.OutputPath = "./test-results.xml"
        
        
        $result = Invoke-Pester -Configuration $pesterConfig
        
        Write-Host ""
        if ($result -and $result.FailedCount -eq 0) {
            Write-Success "All integration tests passed! 🎉"
            Write-Host "  Total: $($result.TotalCount)" -ForegroundColor Gray
            Write-Host "  Passed: $($result.PassedCount)" -ForegroundColor $Colors.Success
            Write-Host "  Duration: $($result.Duration)" -ForegroundColor Gray
            $exitCode = 0
        } elseif ($result) {
            Write-Error "$($result.FailedCount) test(s) failed out of $($result.TotalCount) total tests"
            Write-Host "  Passed: $($result.PassedCount)" -ForegroundColor $Colors.Success
            Write-Host "  Failed: $($result.FailedCount)" -ForegroundColor $Colors.Error
            Write-Host "  Skipped: $($result.SkippedCount)" -ForegroundColor $Colors.Warning
            Write-Host "  Duration: $($result.Duration)" -ForegroundColor Gray
            $exitCode = 1
        } else {
            Write-Warning "Could not determine test results"
            $exitCode = 1
        }
    }
    catch {
        Write-Error "Failed to run Pester tests: $($_.Exception.Message)"
        $exitCode = 1
    }
}
catch {
    Write-Error "Unexpected error: $($_.Exception.Message)"
    $exitCode = 1
}
finally {
    # Cleanup Docker services
    if (-not $SkipDockerCleanup) {
        Write-Step "Cleaning up Docker services..."
        try {
            docker compose -f docker-compose.test.yml down -v --remove-orphans 2>$null
            Write-Success "Docker services stopped and cleaned up"
        }
        catch {
            Write-Warning "Failed to clean up Docker services: $($_.Exception.Message)"
        }
    } else {
        Write-Warning "Skipping Docker cleanup (services left running for debugging)"
        Write-Host "To manually stop services, run: docker compose -f docker-compose.test.yml down -v" -ForegroundColor Gray
        Write-Host "Services available at:" -ForegroundColor Gray
        Write-Host "  - Traefik Dashboard: http://localhost:8080" -ForegroundColor Gray
        Write-Host "  - Test Service: http://localhost:8000/whoami" -ForegroundColor Gray
        Write-Host "  - CrowdSec LAPI: http://localhost:8081/v1/decisions" -ForegroundColor Gray
    }
    
    Write-Host ""
    Write-Host "=========================================================" -ForegroundColor $Colors.Info
    if ($exitCode -eq 0) {
        Write-Host "🏁 Integration tests completed successfully!" -ForegroundColor $Colors.Success
    } else {
        Write-Host "🏁 Integration tests completed with failures!" -ForegroundColor $Colors.Error
    }
    Write-Host ""
}

exit $exitCode 
