# Security Review and Hardening Plan

## Executive Summary

This security review identifies **10 critical and high-severity vulnerabilities** that could allow attackers to hijack servers running this backup agent. The agent accepts commands over a Socket.IO connection with only initial HMAC authentication, then trusts all subsequent messages. Critical issues include command injection vulnerabilities, path traversal risks, missing authorization checks, and unsafe file operations.

## Critical Vulnerabilities

### 1. Command Allowlist Bypass (CRITICAL)
**Location**: `pkg/admin/runner.go:364-375`

The `isAllowed()` function only checks if a command starts with an allowed command, allowing command chaining attacks:

```go
if cmd == allowed || strings.HasPrefix(cmd, allowed+" ") {
    return true
}
```

**Attack**: `"uptime; rm -rf /"` or `"echo hello && cat /etc/passwd"` would pass if "uptime" or "echo" is allowed.

**Fix**: Use exact command matching or parse commands properly. Consider using `exec.Command` with explicit args instead of shell execution.

### 2. Shell Command Injection (CRITICAL)
**Location**: `pkg/admin/runner.go:134-137`

Commands are executed via shell (`/bin/sh -c` or `cmd.exe /C`), making injection possible even with allowlist fixes:

```go
cmd := exec.CommandContext(ctx, "/bin/sh", "-c", req.Command)
```

**Fix**: Parse commands into executable + args, validate against allowlist, then execute directly without shell.

### 3. No Path Validation for Working Directory (HIGH)
**Location**: `pkg/admin/runner.go:139-141`

The `Cwd` field is used without validation:

```go
if strings.TrimSpace(req.Cwd) != "" {
    cmd.Dir = req.Cwd
}
```

**Attack**: Setting `Cwd` to `/etc` or `/root` allows reading sensitive files through relative paths.

**Fix**: Validate `Cwd` against an allowlist or restrict to a sandbox directory.

### 4. Backup Path Traversal (HIGH)
**Location**: `pkg/backup/backup.go:90`

The backup destination path is constructed without validation:

```go
filepath.Join(req.DestRoot, file.Relative)
```

**Attack**: If `DestRoot` is `/tmp/backup` and `file.Relative` is `../../../etc/passwd`, files could be written outside the intended directory.

**Fix**: Use `filepath.Abs()` and validate the final path is within an allowed root directory.

### 5. No Per-Request Authentication (HIGH)
**Location**: `pkg/transport/transport.go:271-312`

Once the Socket.IO connection is established with HMAC auth, all subsequent events are trusted without validation. The `Token` field in `AdminCommand` is ignored.

**Fix**: Implement per-request token validation or session-based authentication.

### 6. SSH Key Validation Missing (MEDIUM)
**Location**: `internal/app/agent.go:206-273`

SSH keys from GitHub are written without validation:

```go
if _, err := file.WriteString(key + "\n"); err != nil {
```

**Attack**: Malicious GitHub account could inject SSH keys or use crafted usernames.

**Fix**: Validate SSH key format before writing. Consider rate limiting and user allowlist.

### 7. Environment Variable Exposure (MEDIUM)
**Location**: `pkg/admin/runner.go:138`

Commands inherit the full environment:

```go
cmd.Env = os.Environ()
```

**Attack**: Secrets in environment variables (API keys, passwords) are exposed to executed commands.

**Fix**: Use a minimal, sanitized environment or explicitly set only required variables.

### 8. Backup Source Path Validation (MEDIUM)
**Location**: `pkg/backup/backup.go:132`

Source directories are cleaned but not validated against traversal:

```go
root := filepath.Clean(dir)
```

**Fix**: Validate source paths are within allowed directories and not symlinks to sensitive locations.

### 9. No Rate Limiting (MEDIUM)
**Location**: Multiple handlers in `internal/app/agent.go`

No rate limiting on commands, shell sessions, or backup operations.

**Fix**: Implement rate limiting per client/session to prevent DoS and brute force.

### 10. Unsafe File Permissions (LOW)
**Location**: `pkg/backup/backup.go:189`

Backup files are created with `0o755` permissions:

```go
os.MkdirAll(filepath.Dir(dest), 0o755)
```

**Fix**: Use more restrictive permissions (e.g., `0o700` for directories, `0o600` for files).

## Exploit Tests

Each security fix must be validated with tests that attempt to exploit the vulnerability. These tests should **fail** (demonstrate the exploit is blocked) after the fix is implemented.

### Test 1: Command Allowlist Bypass Exploit
**File**: `pkg/admin/runner_test.go`

```go
func TestRunCommand_CommandInjection_Blocked(t *testing.T) {
    // Test that command chaining is blocked
    // Attempt: "echo hello; rm -rf /"
    // Expected: Command should be rejected (exit code 126)
    
    // Attempt: "echo hello && cat /etc/passwd"
    // Expected: Command should be rejected
    
    // Attempt: "echo hello | sh"
    // Expected: Command should be rejected
    
    // Attempt: "echo hello`whoami`"
    // Expected: Command should be rejected
}
```

### Test 2: Shell Injection Exploit
**File**: `pkg/admin/runner_test.go`

```go
func TestRunCommand_ShellInjection_Blocked(t *testing.T) {
    // Test that shell metacharacters are blocked
    // Attempt: "$(cat /etc/passwd)"
    // Expected: Command should be rejected or sanitized
    
    // Attempt: "`id`"
    // Expected: Command should be rejected
    
    // Attempt: "$HOME"
    // Expected: Variable expansion should be blocked
}
```

### Test 3: Path Traversal in Cwd Exploit
**File**: `pkg/admin/runner_test.go`

```go
func TestRunCommand_PathTraversal_Cwd_Blocked(t *testing.T) {
    // Test that Cwd cannot access sensitive directories
    // Attempt: Cwd="/etc" with command "cat passwd"
    // Expected: Should be rejected or sandboxed
    
    // Attempt: Cwd="/root" with command "ls -la"
    // Expected: Should be rejected
    
    // Attempt: Cwd="../../../etc" with command "cat passwd"
    // Expected: Should be rejected (path normalization should fail)
}
```

### Test 4: Backup Path Traversal Exploit
**File**: `pkg/backup/backup_test.go`

```go
func TestBackup_PathTraversal_Blocked(t *testing.T) {
    // Test that backup cannot write outside DestRoot
    // Attempt: DestRoot="/tmp/backup", file.Relative="../../../etc/passwd"
    // Expected: Should be rejected or sanitized
    
    // Attempt: DestRoot="/tmp/backup", file.Relative="../../root/.ssh/id_rsa"
    // Expected: Should be rejected
    
    // Attempt: DestRoot="/tmp/backup", file.Relative="/etc/passwd" (absolute path)
    // Expected: Should be rejected
}
```

### Test 5: Backup Source Path Traversal Exploit
**File**: `pkg/backup/backup_test.go`

```go
func TestBackup_SourcePathTraversal_Blocked(t *testing.T) {
    // Test that backup cannot read from unauthorized directories
    // Attempt: SourceDirs=["/etc"]
    // Expected: Should be rejected if not in allowlist
    
    // Attempt: SourceDirs=["../../../etc"]
    // Expected: Should be rejected
    
    // Attempt: SourceDirs with symlink to /etc
    // Expected: Should resolve and validate, reject if not allowed
}
```

### Test 6: Per-Request Authentication Exploit
**File**: `pkg/transport/transport_test.go` or `internal/app/agent_test.go`

```go
func TestAdminRun_UnauthenticatedRequest_Blocked(t *testing.T) {
    // Test that commands without valid token are rejected
    // Attempt: AdminCommand with empty/invalid token
    // Expected: Should be rejected
    
    // Attempt: AdminCommand with expired token
    // Expected: Should be rejected
    
    // Attempt: AdminCommand with token from different session
    // Expected: Should be rejected
}
```

### Test 7: SSH Key Validation Exploit
**File**: `internal/app/agent_test.go`

```go
func TestSyncKeys_InvalidSSHKey_Blocked(t *testing.T) {
    // Test that invalid SSH keys are rejected
    // Attempt: Sync keys with malformed key (not starting with ssh-rsa, ssh-ed25519, etc.)
    // Expected: Should be rejected
    
    // Attempt: Sync keys with key containing newlines or special chars
    // Expected: Should be sanitized or rejected
    
    // Attempt: Sync keys with extremely long key (DoS attempt)
    // Expected: Should be rejected or truncated
}
```

### Test 8: Environment Variable Exposure Exploit
**File**: `pkg/admin/runner_test.go`

```go
func TestRunCommand_EnvironmentSanitization(t *testing.T) {
    // Test that sensitive env vars are not exposed
    // Setup: Set env vars like API_KEY, PASSWORD, SECRET
    // Attempt: Command "env | grep -i secret"
    // Expected: Sensitive vars should not appear in output
    
    // Attempt: Command "echo $API_KEY"
    // Expected: Variable should be empty or undefined
}
```

### Test 9: Rate Limiting Exploit
**File**: `pkg/admin/runner_test.go` or `internal/app/agent_test.go`

```go
func TestAdminRun_RateLimit_Enforced(t *testing.T) {
    // Test that rapid command execution is rate limited
    // Attempt: Send 100 commands in 1 second
    // Expected: Commands after limit should be rejected or queued
    
    // Attempt: Rapid shell session creation
    // Expected: Should be rate limited
}
```

### Test 10: File Permissions Exploit
**File**: `pkg/backup/backup_test.go`

```go
func TestBackup_FilePermissions_Secure(t *testing.T) {
    // Test that backup files have restrictive permissions
    // After backup: Check file permissions
    // Expected: Files should be 0o600, directories 0o700
    
    // Attempt: Backup file with sensitive content
    // Expected: Permissions should prevent world/group read
}
```

## Implementation Strategy

### Phase 1: Critical Fixes (Immediate)
1. Fix command allowlist bypass - implement strict command parsing
2. Remove shell execution - use direct exec.Command with args
3. Add path validation for Cwd and backup paths
4. Implement per-request token validation

### Phase 2: High Priority
5. Add SSH key format validation
6. Sanitize environment variables
7. Add source path validation for backups

### Phase 3: Hardening
8. Implement rate limiting
9. Fix file permissions
10. Add comprehensive logging/auditing for security events

## Files to Modify

- `pkg/admin/runner.go` - Command execution and validation
- `pkg/backup/backup.go` - Path validation
- `internal/app/agent.go` - SSH key validation, request auth
- `pkg/transport/transport.go` - Per-request authentication
- `pkg/config/config.go` - Add security configuration options

## Test Files to Create/Update

- `pkg/admin/runner_test.go` - Add exploit tests for command injection, path traversal, env exposure
- `pkg/backup/backup_test.go` - Add exploit tests for path traversal
- `internal/app/agent_test.go` - Add exploit tests for SSH key validation, authentication
- `pkg/transport/transport_test.go` - Add exploit tests for authentication (if file exists)

## Testing Requirements

- All exploit tests should **initially pass** (demonstrating the vulnerability exists)
- After implementing fixes, exploit tests should **fail** (demonstrating the exploit is blocked)
- Each test should have clear comments explaining the attack vector
- Tests should use descriptive names like `TestXxx_ExploitName_Blocked`
- Consider using table-driven tests for multiple exploit variations
