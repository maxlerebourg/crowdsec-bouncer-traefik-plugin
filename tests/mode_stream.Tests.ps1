#!/usr/bin/env pwsh

# Stream Mode Tests for CrowdSec Bouncer Traefik Plugin
# Tests bouncer behavior in 'stream' mode (local cache with periodic updates)

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

Describe "CrowdSec Bouncer Stream Mode Tests" {
    
    Context "Stream Mode Tests" -Tag "stream" {
        
        BeforeEach {
            # Clear Traefik access logs for clean test isolation
            Clear-TraefikAccessLogs
            # Clean up any existing decisions
            foreach ($ip in $script:TestIPs.Values) {
                try { Remove-TestDecision -IP $ip } catch { }
            }
        }
        
        It "Should handle decisions with cache updates" {
            # Add a decision for the client IP that will be seen by the stream mode bouncer
            Add-TestDecision -IP $script:TestIPs.BannedIP -Type "ban"
            
            # Stream mode initial sync can take time, but keep timeout reasonable
            $result = Wait-ForCondition -Description "Stream mode to block IP $($script:TestIPs.BannedIP)" -TimeoutSeconds 30 -RetryIntervalSeconds 2 -Condition {
                $response = Test-HttpRequest -Endpoint "/stream" -IP $script:TestIPs.BannedIP -TraefikUrl $script:TraefikUrl
                return ($response.StatusCode -in @(403, 429))
            }
            
            $result.Success | Should -Be $true -Because "Stream mode should eventually block the banned IP"
            
            # Clean up
            Remove-TestDecision -IP $script:TestIPs.BannedIP
            
            # Wait for stream mode to allow the IP again (should be faster after initial sync)
            $result = Wait-ForCondition -Description "Stream mode to allow IP $($script:TestIPs.BannedIP) after decision removal" -TimeoutSeconds 30 -RetryIntervalSeconds 2 -Condition {
                $response = Test-HttpRequest -Endpoint "/stream" -IP $script:TestIPs.BannedIP -TraefikUrl $script:TraefikUrl
                return ($response.StatusCode -eq 200)
            }
            
            $result.Success | Should -Be $true -Because "Stream mode should eventually allow the IP after decision removal"
        }
        
        It "Should handle decision updates within timeout" {
            # This test ensures the bouncer can handle updates within the configured timeout
            $measureTime = Measure-Command {
                Add-TestDecision -IP $script:TestIPs.BannedIP -Type "ban"
                
                # Wait for stream mode to block the IP (initial sync can be slow)
                $result = Wait-ForCondition -Description "Stream mode to block IP" -TimeoutSeconds 30 -RetryIntervalSeconds 2 -Silent -Condition {
                    $response = Test-HttpRequest -Endpoint "/stream" -IP $script:TestIPs.BannedIP -TraefikUrl $script:TraefikUrl
                    return ($response.StatusCode -in @(403, 429))
                }
                
                $result.Success | Should -Be $true -Because "Stream mode should block the IP within timeout"
                Remove-TestDecision -IP $script:TestIPs.BannedIP
            }
            
            # The entire operation should complete within the configured timeout
            $measureTime.TotalSeconds | Should -BeLessThan $script:HttpTimeoutSeconds
        }
    }
}

