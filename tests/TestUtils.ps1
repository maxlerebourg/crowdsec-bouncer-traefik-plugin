#!/usr/bin/env pwsh

# Shared utility functions for CrowdSec Bouncer integration tests
# This file contains reusable helper functions for all test suites

# Helper function to call CrowdSec LAPI
function Invoke-CrowdSecAPI {
    param(
        [string]$Endpoint,
        [string]$Method = "GET",
        [object]$Body = $null,
        [int]$TimeoutSec = 10,
        [string]$ApiKey = "40796d93c2958f9e58345514e67740e5",
        [string]$CrowdSecApiUrl = "http://localhost:8081"
    )
    
    $headers = @{
        "X-Api-Key" = $ApiKey
        "Content-Type" = "application/json"
    }
    
    $uri = "$CrowdSecApiUrl$Endpoint"
    
    try {
        if ($Body) {
            $jsonBody = $Body | ConvertTo-Json -Depth 10
            return Invoke-RestMethod -Uri $uri -Method $Method -Headers $headers -Body $jsonBody -TimeoutSec $TimeoutSec
        } else {
            return Invoke-RestMethod -Uri $uri -Method $Method -Headers $headers -TimeoutSec $TimeoutSec
        }
    }
    catch {
        Write-Host "❌ LAPI call failed: $($_.Exception.Message)" -ForegroundColor Red
        throw
    }
}

# Helper function to create a decision using cscli
function Add-TestDecision {
    param(
        [string]$IP,
        [string]$Type = "ban",
        [string]$Duration = "1h",
        [string]$Scenario = "integration-test",
        [string]$Reason = "Integration test decision"
    )
    
    Write-Host "➕ Adding $Type decision for $IP" -ForegroundColor Yellow
    
    $addCommand = "cscli decisions add --ip $IP --duration $Duration --type $Type --reason '$Reason'"
    $result = docker exec crowdsec-test sh -c $addCommand
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to add decision: $result"
    }
    
    Write-Host "✅ Decision added successfully via cscli" -ForegroundColor Green
    return $true
}

# Helper function to remove decisions for an IP using cscli
function Remove-TestDecision {
    param(
        [string]$IP
    )
    
    $result = docker exec crowdsec-test cscli decisions delete --ip $IP 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "⚠️ Failed to remove decisions for $IP" -ForegroundColor Yellow
    } else {
        Write-Host "✅ Removed decisions for $IP" -ForegroundColor Green
    }
    return $true
}

# Helper function to test HTTP request
function Test-HttpRequest {
    param(
        [string]$Endpoint,
        [string]$IP,
        [int]$ExpectedStatusCode = 200,
        [string]$ExpectedContent = $null,
        [int]$TimeoutSec = 10,
        [string]$TraefikUrl = "http://localhost:8000"
    )
    
    $headers = @{
        "X-Forwarded-For" = $IP
        "User-Agent" = "Integration-Test-Client"
    }
    
    try {
        $response = Invoke-WebRequest -Uri "$TraefikUrl$Endpoint" -Headers $headers -TimeoutSec $TimeoutSec -UseBasicParsing
        
        return @{
            StatusCode = $response.StatusCode
            Content = $response.Content
            Success = $true
        }
    }
    catch {
        $statusCode = 0
        $content = ""
        
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
            $content = $_.Exception.Response.Content ?? ""
        }
        
        return @{
            StatusCode = $statusCode
            Content = $content
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

# Helper function to wait for a specific HTTP status code with timeout
function Wait-ForHttpStatus {
    param(
        [string]$Url,
        [hashtable]$Headers = @{},
        [int[]]$ExpectedStatusCodes = @(200),
        [int]$TimeoutSeconds = 15,
        [int]$RetryIntervalSeconds = 1
    )
    
    $elapsed = 0
    $lastStatusCode = 0
    $lastError = ""
    
    do {
        try {
            $response = Invoke-WebRequest -Uri $Url -Headers $Headers -UseBasicParsing -TimeoutSec 5
            $lastStatusCode = $response.StatusCode
            if ($ExpectedStatusCodes -contains $lastStatusCode) {
                return @{
                    Success = $true
                    StatusCode = $lastStatusCode
                    TimeTaken = $elapsed
                }
            }
        }
        catch {
            if ($_.Exception.Response) {
                $lastStatusCode = [int]$_.Exception.Response.StatusCode
                if ($ExpectedStatusCodes -contains $lastStatusCode) {
                    return @{
                        Success = $true
                        StatusCode = $lastStatusCode
                        TimeTaken = $elapsed
                    }
                }
            }
            $lastError = $_.Exception.Message
        }
        
        Start-Sleep $RetryIntervalSeconds
        $elapsed += $RetryIntervalSeconds
        
    } while ($elapsed -lt $TimeoutSeconds)
    
    return @{
        Success = $false
        StatusCode = $lastStatusCode
        TimeTaken = $elapsed
        Error = $lastError
    }
}

# Helper function to wait for a condition to be met with retry logic
function Wait-ForCondition {
    param(
        [scriptblock]$Condition,
        [string]$Description = "Condition",
        [int]$TimeoutSeconds = 30,
        [int]$RetryIntervalSeconds = 1,
        [switch]$Silent
    )
    
    $elapsed = 0
    $lastError = ""
    
    if (-not $Silent) {
        Write-Host "🔄 Waiting for $Description..." -ForegroundColor Cyan
    }
    
    do {
        try {
            $result = & $Condition
            if ($result) {
                if (-not $Silent) {
                    Write-Host "✅ $Description met after $elapsed seconds" -ForegroundColor Green
                }
                return @{
                    Success = $true
                    TimeTaken = $elapsed
                }
            }
        }
        catch {
            $lastError = $_.Exception.Message
        }
        
        Start-Sleep $RetryIntervalSeconds
        $elapsed += $RetryIntervalSeconds
        
        if ($elapsed % 10 -eq 0 -and -not $Silent) {
            Write-Host "  Still waiting for $Description... ($elapsed/$TimeoutSeconds seconds)" -ForegroundColor Gray
        }
        
    } while ($elapsed -lt $TimeoutSeconds)
    
    if (-not $Silent) {
        Write-Host "❌ $Description not met within $TimeoutSeconds seconds" -ForegroundColor Red
        if ($lastError) {
            Write-Host "  Last error: $lastError" -ForegroundColor Yellow
        }
    }
    
    return @{
        Success = $false
        TimeTaken = $elapsed
        Error = $lastError
    }
}

# Helper function to read and parse Traefik access logs
function Get-TraefikAccessLogs {
    param(
        [string]$ContainerName = "traefik-test",
        [string]$LogPath = "/var/log/traefik/access.log"
    )
    
    # Read the access logs
    Write-Host "📋 Reading Traefik access logs..." -ForegroundColor Yellow
    $logContent = docker exec $ContainerName cat $LogPath
    
    if ([string]::IsNullOrWhiteSpace($logContent)) {
        Write-Host "⚠️ No access log content found" -ForegroundColor Yellow
        return @{
            Success = $false
            RawContent = ""
            LogEntries = @()
            Error = "No access log content found"
        }
    }
    
    Write-Host "📄 Access log content:" -ForegroundColor Gray
    Write-Host $logContent -ForegroundColor Gray
    
    # Parse the JSON log entries
    $logLines = $logContent -split "`n" | Where-Object { $_.Trim() -ne "" }
    $parsedEntries = @()
    
    foreach ($line in $logLines) {
        try {
            $logEntry = $line | ConvertFrom-Json
            $parsedEntries += $logEntry
        }
        catch {
            Write-Host "⚠️ Could not parse log line: $line" -ForegroundColor Yellow
        }
    }
    
    return @{
        Success = $true
        RawContent = $logContent
        LogEntries = $parsedEntries
        Count = $parsedEntries.Count
    }
}

# Helper function to clear Traefik access logs (with backup for CI debugging)
function Clear-TraefikAccessLogs {
    param(
        [string]$ContainerName = "traefik-test",
        [string]$LogPath = "/var/log/traefik/access.log"
    )
    
    Write-Host "🧹 Clearing Traefik access logs..." -ForegroundColor Yellow
    
    # Append current log contents to backup for CI debugging before clearing
    docker exec $ContainerName sh -c "cat $LogPath >> ${LogPath}.bak 2>/dev/null || touch ${LogPath}.bak" 2>$null
    
    # Clear the main log file
    docker exec $ContainerName sh -c "echo '' > $LogPath" 2>$null
}

# Helper function to find specific log entries using a condition callback
function Find-TraefikLogEntry {
    param(
        [object[]]$LogEntries,
        [scriptblock]$Condition,
        [string]$Description = "matching log entry"
    )
    
    foreach ($logEntry in $LogEntries) {
        try {
            # Execute the condition callback with the log entry
            $matches = & $Condition $logEntry
            if ($matches) {
                Write-Host "✅ Found $Description" -ForegroundColor Green
                return @{
                    Found = $true
                    LogEntry = $logEntry
                }
            }
        }
        catch {
            # Skip invalid log entries or condition errors
            Write-Host "⚠️ Error evaluating condition for log entry" -ForegroundColor Yellow
        }
    }
    
    Write-Host "❌ No $Description found in access logs" -ForegroundColor Red
    Write-Host "Available log entries:" -ForegroundColor Yellow
    foreach ($logEntry in $LogEntries) {
        try {
            Write-Host "  Path: $($logEntry.RequestPath), Status: $($logEntry.DownstreamStatus)" -ForegroundColor Yellow
        }
        catch { }
    }
    
    return @{
        Found = $false
        LogEntry = $null
    }
}
