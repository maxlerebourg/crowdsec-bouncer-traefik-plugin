#!/usr/bin/env pwsh

# None Mode Tests for CrowdSec Bouncer Traefik Plugin
# Tests bouncer behavior in 'none' mode (immediate LAPI queries, no caching)

BeforeAll {
    # Import shared test utilities
    . "$PSScriptRoot/TestUtils.ps1"
    
    # Test configuration
    $script:TraefikUrl = "http://localhost:8000"
    $script:CrowdSecApiUrl = "http://localhost:8081"
    $script:ApiKey = "40796d93c2958f9e58345514e67740e5"
    $script:HttpTimeoutSeconds = [int]($env:HTTP_TIMEOUT_SECONDS ?? 30)
    
    # Test IP addresses - using Docker network IPs that the bouncer actually sees
    $script:TestIPs = @{
        BannedIP = "172.19.0.1"
        CaptchaIP = "172.19.0.2" 
        CleanIP = "172.19.0.3"
    }
    
    # Wait for CrowdSec LAPI to be ready
    $result = Wait-ForCondition -Description "CrowdSec LAPI to be ready" -TimeoutSeconds 60 -RetryIntervalSeconds 2 -Condition {
        Invoke-CrowdSecAPI -Endpoint "/v1/decisions?limit=1" -TimeoutSec 5 -ApiKey $script:ApiKey -CrowdSecApiUrl $script:CrowdSecApiUrl
        return $true
    }
    
    if (-not $result.Success) {
        throw "❌ CrowdSec LAPI failed to become ready"
    }
}

Describe "CrowdSec Bouncer None Mode Tests" {
    
    Context "Basic Bouncer Functionality" -Tag "none" {
        
        BeforeEach {
            Clear-TraefikAccessLogs
            Remove-AllTestDecisions
        }
        
        It "Should allow clean IP through" {
            $response = Test-HttpRequest -Endpoint "/whoami" -IP $script:TestIPs.CleanIP -TraefikUrl $script:TraefikUrl
            $response.Success | Should -Be $true
            $response.StatusCode | Should -Be 200
            $response.Content | Should -Match "Hostname"
        }
        
        It "Should block banned IP immediately" {
            # Add ban decision
            Add-TestDecision -IP $script:TestIPs.BannedIP -Type "ban"
            
            # In 'none' mode, bouncer queries LAPI immediately - no wait needed
            
            # Test that IP is blocked
            $response = Test-HttpRequest -Endpoint "/whoami" -IP $script:TestIPs.BannedIP -TraefikUrl $script:TraefikUrl
            $response.StatusCode | Should -BeIn @(403, 429)
        }
        
        It "Should unblock IP immediately after decision removal" {
            # Add ban decision
            Add-TestDecision -IP $script:TestIPs.BannedIP -Type "ban"
            
            # Verify it's blocked
            $response = Test-HttpRequest -Endpoint "/whoami" -IP $script:TestIPs.BannedIP -TraefikUrl $script:TraefikUrl
            $response.StatusCode | Should -BeIn @(403, 429)
            
            # Remove decision
            Remove-TestDecision -IP $script:TestIPs.BannedIP
            
            # In 'none' mode, bouncer queries LAPI immediately - no wait needed
            
            # Verify it's now allowed
            $response = Test-HttpRequest -Endpoint "/whoami" -IP $script:TestIPs.BannedIP -TraefikUrl $script:TraefikUrl
            $response.Success | Should -Be $true
            $response.StatusCode | Should -Be 200
        }
    }
    
    Context "Performance Tests" -Tag "none" {
        
        BeforeEach {
            Clear-TraefikAccessLogs
            Remove-AllTestDecisions
        }
        
        It "Should handle requests within reasonable time" {
            $measureTime = Measure-Command {
                $response = Test-HttpRequest -Endpoint "/whoami" -IP $script:TestIPs.CleanIP -TraefikUrl $script:TraefikUrl
                $response.Success | Should -Be $true
            }
            
            # Request should complete within 5 seconds
            $measureTime.TotalSeconds | Should -BeLessThan 5
        }
        
        It "Should handle blocked requests efficiently" {
            # Add ban decision
            Add-TestDecision -IP $script:TestIPs.BannedIP -Type "ban"
            
            # In 'none' mode, bouncer queries LAPI immediately - no wait needed
            
            $measureTime = Measure-Command {
                $response = Test-HttpRequest -Endpoint "/whoami" -IP $script:TestIPs.BannedIP -TraefikUrl $script:TraefikUrl
                $response.StatusCode | Should -BeIn @(403, 429)
            }
            
            # Blocked request should be fast (no backend processing)
            $measureTime.TotalSeconds | Should -BeLessThan 2
        }
    }
}

