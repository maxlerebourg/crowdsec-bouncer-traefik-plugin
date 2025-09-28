#!/usr/bin/env pwsh

# Simple Integration Test for CrowdSec Bouncer
# Focus: Prove basic functionality works

BeforeAll {
    # Import shared test utilities
    . "$PSScriptRoot/TestUtils.ps1"
    
    $script:TraefikUrl = "http://localhost:8000"
    $script:CrowdSecApiUrl = "http://localhost:8081"
    $script:TestIP = "172.19.0.1"
    
    # Wait for Traefik to be ready
    $result = Wait-ForCondition -Description "Traefik to be ready" -TimeoutSeconds 30 -RetryIntervalSeconds 2 -Condition {
        try {
            $response = Invoke-WebRequest -Uri "http://localhost:8000/disabled" -TimeoutSec 3 -UseBasicParsing
            return ($response.StatusCode -eq 200)
        }
        catch {
            return $false
        }
    }
    
    if (-not $result.Success) {
        throw "❌ Traefik failed to become ready"
    }
    
    # Set up bouncer API key for reading decisions (cscli handles writing)
    Write-Host "🔍 Setting up CrowdSec API..." -ForegroundColor Yellow
    $script:BouncerApiKey = "40796d93c2958f9e58345514e67740e5"
    
    # Test bouncer API
    Write-Host "🔄 Testing CrowdSec bouncer API..." -ForegroundColor Cyan
    try {
        $response = Invoke-CrowdSecAPI -Endpoint "/v1/decisions?limit=1" -ApiKey $script:BouncerApiKey -CrowdSecApiUrl $script:CrowdSecApiUrl
        Write-Host "✅ CrowdSec bouncer API is working!" -ForegroundColor Green
    }
    catch {
        Write-Host "❌ Bouncer API test failed: $($_.Exception.Message)" -ForegroundColor Red
        throw "CrowdSec bouncer API not accessible"
    }
}

Describe "Basic CrowdSec Bouncer Integration Test" {
    
    BeforeEach {
        # Clear Traefik access logs for clean test isolation
        Clear-TraefikAccessLogs
    }
    
    It "Should allow access when no decision exists" {
        # Test that we can access the endpoint normally
        $response = Test-HttpRequest -Endpoint "/whoami" -IP $script:TestIP -TraefikUrl $script:TraefikUrl
        $response.StatusCode | Should -Be 200 -Because "Clean IP should be able to access endpoint"
    }
    
    It "Should block access after adding a ban decision" {
        # Add a ban decision using cscli (simpler than API)
        Write-Host "➕ Adding ban decision for $script:TestIP" -ForegroundColor Yellow
        
        # Add a ban decision
        Add-TestDecision -IP $script:TestIP -Type "ban" -Reason "Integration test"
        
        # With 0 cache time, the bouncer queries LAPI directly - no wait needed!
        
        # Now test that the IP is blocked
        $response = Test-HttpRequest -Endpoint "/whoami" -IP $script:TestIP -TraefikUrl $script:TraefikUrl
        $response.StatusCode | Should -BeIn @(403, 429) -Because "IP should be blocked after ban decision"
    }
    
    It "Should allow access after removing the ban decision" {
        # Remove the decision
        Remove-TestDecision -IP $script:TestIP
        
        # With 0 cache time, the bouncer queries LAPI directly - no wait needed!
        
        # Now test that the IP can access again
        $response = Test-HttpRequest -Endpoint "/whoami" -IP $script:TestIP -TraefikUrl $script:TraefikUrl
        $response.StatusCode | Should -Be 200 -Because "IP should be able to access endpoint after decision removal"
    }

    It "Should include custom remediation header in Traefik access logs when blocking requests" {
        # Clear logs first, then add a ban decision
        Clear-TraefikAccessLogs
        Add-TestDecision -IP $script:TestIP -Type "ban" -Reason "Custom header test"
        
        # Make a request to the endpoint with custom remediation headers configured
        Write-Host "🌐 Making request to remediation-headers endpoint..." -ForegroundColor Yellow
        $response = Test-HttpRequest -Endpoint "/remediation-headers" -IP $script:TestIP -TraefikUrl $script:TraefikUrl
        
        # We expect this to be blocked (403), but we're interested in the headers
        $response.StatusCode | Should -BeIn @(403, 429) -Because "Banned IP should be blocked"
        
        # Get and parse Traefik access logs
        $logResult = Get-TraefikAccessLogs
        
        if (-not $logResult.Success) {
            throw $logResult.Error
        }
        
        # Find log entry for remediation-headers endpoint with ban remediation header
        $result = Find-TraefikLogEntry -LogEntries $logResult.LogEntries -Description "remediation-headers log entry with ban header" -Condition {
            param($logEntry)
            return ($logEntry.RequestPath -eq "/remediation-headers" -and $logEntry.'downstream_X-Crowdsec-Remediation' -eq "ban")
        }
        
        $result.Found | Should -Be $true -Because "Custom remediation header should appear in Traefik access logs when blocking requests"
        
        if ($result.Found) {
            $remediationHeader = $result.LogEntry.'downstream_X-Crowdsec-Remediation'
            Write-Host "  Header value: $remediationHeader" -ForegroundColor Green
            Write-Host "  Status code: $($result.LogEntry.DownstreamStatus)" -ForegroundColor Green
        }
        
        # Cleanup: Remove the decision
        Remove-TestDecision -IP $script:TestIP
    }
}

Describe "CrowdSec Bouncer General Tests" {
    
    BeforeEach {
        # Clear Traefik access logs for clean test isolation
        Clear-TraefikAccessLogs
    }
    
    Context "Service Health Checks" {
        It "CrowdSec LAPI should be accessible" {
            # Test that LAPI responds (null response is valid when no decisions exist)
            { Invoke-CrowdSecAPI -Endpoint "/v1/decisions?limit=1" -ApiKey $script:BouncerApiKey -CrowdSecApiUrl $script:CrowdSecApiUrl } | Should -Not -Throw
        }
        
        It "Traefik should be accessible" {
            $response = Test-HttpRequest -Endpoint "/whoami" -IP "172.19.0.3" -TraefikUrl $script:TraefikUrl
            $response.Success | Should -Be $true
            $response.StatusCode | Should -Be 200
        }
    }
    
    Context "Disabled Bouncer Tests" -Tag "disabled" {
        
        It "Should allow all traffic when bouncer is disabled" {
            # Test disabled endpoint should always allow traffic
            $response = Test-HttpRequest -Endpoint "/disabled" -IP $script:TestIP -TraefikUrl $script:TraefikUrl
            $response.Success | Should -Be $true
            $response.StatusCode | Should -Be 200
        }
    }
    
    Context "Error Handling Tests" -Tag "error" {
        
        It "Should handle invalid decisions gracefully" {
            # Try to add decision with invalid IP
            { Add-TestDecision -IP "invalid.ip" -Type "ban" } | Should -Throw
        }
        
        It "Should handle LAPI connectivity issues" {
            # Test with wrong API key - should throw an exception
            { Invoke-CrowdSecAPI -Endpoint "/v1/decisions?limit=1" -ApiKey "invalid-key" -CrowdSecApiUrl $script:CrowdSecApiUrl } | Should -Throw
        }
    }
}

