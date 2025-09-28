#!/usr/bin/env pwsh

# Captcha Remediation Tests for CrowdSec Bouncer Traefik Plugin
# Tests bouncer behavior when applying captcha remediation

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
        BannedIP  = "172.19.0.1"
        CaptchaIP = "172.19.0.2" 
        CleanIP   = "172.19.0.3"
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

Describe "CrowdSec Bouncer Captcha Remediation Tests" {
    
    Context "Captcha Remediation Tests" -Tag "captcha" {
        
        BeforeEach {
            # Clear Traefik access logs for clean test isolation
            Clear-TraefikAccessLogs
            # Clean up any existing decisions
            foreach ($ip in $script:TestIPs.Values) {
                try { Remove-TestDecision -IP $ip } catch { }
            }
        }
        
        It "Should show captcha remediation for captcha decision" {
            # Add captcha decision for the IP the bouncer actually sees
            Add-TestDecision -IP $script:TestIPs.BannedIP -Type "captcha"
            
            # Test captcha endpoint
            $response = Test-HttpRequest -Endpoint "/captcha" -IP $script:TestIPs.CaptchaIP -TraefikUrl $script:TraefikUrl
            $response.StatusCode | Should -BeIn @(200, 429)
            
            # If captcha is working, response should contain captcha content
            if ($response.StatusCode -eq 200) {
                $response.Content | Should -Match "captcha|challenge"
            }
            
            # Verify custom remediation header in Traefik access logs
            $logResult = Get-TraefikAccessLogs
            $logResult.Success | Should -Be $true -Because "Should be able to read Traefik access logs"
            
            # Find log entry for captcha endpoint with remediation header
            $result = Find-TraefikLogEntry -LogEntries $logResult.LogEntries -Description "captcha log entry with remediation header" -Condition {
                param($logEntry)
                return ($logEntry.RequestPath -eq "/captcha" -and $logEntry.'downstream_X-Crowdsec-Remediation' -eq "captcha")
            }
            
            $result.Found | Should -Be $true -Because "Custom remediation header should appear in Traefik access logs for captcha decisions"
            
            if ($result.Found) {
                $remediationHeader = $result.LogEntry.'downstream_X-Crowdsec-Remediation'
                Write-Host "  Header value: $remediationHeader" -ForegroundColor Green
                Write-Host "  Status code: $($result.LogEntry.DownstreamStatus)" -ForegroundColor Green
            }
        }
        
        It "Should fallback to ban when captcha is not configured" {
            # Add captcha decision for the IP the bouncer actually sees
            Add-TestDecision -IP $script:TestIPs.BannedIP -Type "captcha"
            
            # Test an endpoint without captcha configuration (should fallback to ban)
            $response = Test-HttpRequest -Endpoint "/whoami" -IP $script:TestIPs.CaptchaIP -TraefikUrl $script:TraefikUrl
            $response.StatusCode | Should -BeIn @(403, 429) -Because "Should fallback to ban when captcha is not configured"
            
            # Verify custom remediation header shows 'ban' fallback
            $logResult = Get-TraefikAccessLogs
            $logResult.Success | Should -Be $true -Because "Should be able to read Traefik access logs"
            
            # Find log entry for whoami endpoint with ban remediation header (fallback)
            $result = Find-TraefikLogEntry -LogEntries $logResult.LogEntries -Description "whoami log entry with ban fallback header" -Condition {
                param($logEntry)
                return ($logEntry.RequestPath -eq "/whoami" -and $logEntry.'downstream_X-Crowdsec-Remediation' -eq "ban")
            }
            
            $result.Found | Should -Be $true -Because "Should fallback to ban remediation when captcha is not configured"
            
            if ($result.Found) {
                $remediationHeader = $result.LogEntry.'downstream_X-Crowdsec-Remediation'
                Write-Host "  Fallback header value: $remediationHeader" -ForegroundColor Green
                Write-Host "  Status code: $($result.LogEntry.DownstreamStatus)" -ForegroundColor Green
            }
        }
        
        It "Should show ban remediation for ban decision even on captcha endpoint" {
            # Add ban decision (not captcha) for the IP the bouncer actually sees
            Add-TestDecision -IP $script:TestIPs.BannedIP -Type "ban"
            
            # Test captcha endpoint with ban decision (should show ban, not captcha)
            $response = Test-HttpRequest -Endpoint "/captcha" -IP $script:TestIPs.CaptchaIP -TraefikUrl $script:TraefikUrl
            $response.StatusCode | Should -BeIn @(403, 429) -Because "Ban decision should block request even on captcha endpoint"
            
            # Verify custom remediation header shows 'ban' (decision type overrides endpoint config)
            $logResult = Get-TraefikAccessLogs
            $logResult.Success | Should -Be $true -Because "Should be able to read Traefik access logs"
            
            # Find log entry for captcha endpoint with ban remediation header
            $result = Find-TraefikLogEntry -LogEntries $logResult.LogEntries -Description "captcha endpoint log entry with ban header" -Condition {
                param($logEntry)
                return ($logEntry.RequestPath -eq "/captcha" -and $logEntry.'downstream_X-Crowdsec-Remediation' -eq "ban")
            }
            
            $result.Found | Should -Be $true -Because "Ban decision should result in ban remediation even on captcha-configured endpoint"
            
            if ($result.Found) {
                $remediationHeader = $result.LogEntry.'downstream_X-Crowdsec-Remediation'
                Write-Host "  Ban header value: $remediationHeader" -ForegroundColor Green
                Write-Host "  Status code: $($result.LogEntry.DownstreamStatus)" -ForegroundColor Green
            }
        }
    }
}

