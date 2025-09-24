#!/bin/bash

# Ephemeral K9s Session Script with Automatic Cleanup
# This script runs in disposable containers and cleans up when sessions end

SESSION_ID="${SESSION_ID:-$(uuidgen)}"
USER_ID="${USER_ID:-anonymous}"
SESSION_TIMEOUT="${SESSION_TIMEOUT:-3600}"

echo "🚀 K9s Ephemeral Session"
echo "======================="
echo "👤 User: $USER_ID"
echo "🔑 Session: $SESSION_ID"
echo "⏰ Timeout: ${SESSION_TIMEOUT}s"
echo ""

# Performance and security optimizations
export TERM=xterm-256color
export K9S_CONFIG_DIR="/root/.config/k9s"
export KUBECTL_CLI_PRINT_PROGRESS=false
export HISTSIZE=50
export HISTFILESIZE=50

# Security: Ensure no cached tokens from previous sessions (shouldn't exist in ephemeral containers)
cleanup_any_existing_tokens() {
    rm -rf ~/.cache/kubelogin* 2>/dev/null || true
    rm -rf ~/.kube/cache 2>/dev/null || true
    rm -rf ~/.kube/http-cache 2>/dev/null || true
    unset KUBERNETES_EXEC_INFO KUBECONFIG_EXEC_CACHE OAUTH_ACCESS_TOKEN || true
}

# Session cleanup on exit
cleanup_session() {
    echo ""
    echo "🧹 Session $SESSION_ID ending..."
    cleanup_any_existing_tokens
    echo "✅ Session cleaned up"
    echo "👋 Goodbye!"
    
    # Force exit to ensure container terminates
    exit 0
}

# Automatic timeout cleanup
timeout_cleanup() {
    echo ""
    echo "⏰ Session timeout reached after ${SESSION_TIMEOUT}s"
    cleanup_session
}

# Set up signal traps for cleanup
trap cleanup_session EXIT SIGTERM SIGINT SIGHUP
trap timeout_cleanup SIGALRM

# Start background timeout (in seconds)
(sleep $SESSION_TIMEOUT && kill -ALRM $$) &
TIMEOUT_PID=$!

echo "🛡️  Security: This is an isolated ephemeral container"
echo "🗑️  Auto-cleanup: Container will be destroyed when you disconnect"
echo ""

# Initial security cleanup (should be empty in ephemeral containers)
cleanup_any_existing_tokens

echo "💡 Available commands:"
echo "   • k9s           - Launch k9s (will prompt for OIDC auth)"
echo "   • kubectl get nodes  - Test cluster connectivity"
echo "   • kubectl auth whoami - Check authentication status"  
echo "   • exit          - End session (destroys container)"
echo ""
echo "🔐 OIDC Authentication (when running k9s):"
echo "   • Open new browser tab to complete device code flow"
echo "   • https://login.microsoftonline.com/device"
echo ""

# Create session-specific bashrc
cat > /tmp/session_bashrc << EOF
# Session-specific configuration
export PS1="k9s-$SESSION_ID:\w$ "

# Cleanup function available in shell
cleanup_session() {
    echo ""
    echo "🧹 Session $SESSION_ID ending..."
    rm -rf ~/.cache/kubelogin* ~/.kube/cache ~/.kube/http-cache 2>/dev/null || true
    echo "✅ Session cleaned up"
    echo "👋 Goodbye!"
    exit 0
}

# Set up signal traps in interactive shell
trap cleanup_session EXIT SIGTERM SIGINT SIGHUP

# Helpful aliases
alias k='kubectl'
alias kgn='kubectl get nodes'  
alias kwho='kubectl auth whoami'
alias session-info='echo "Session: $SESSION_ID, User: $USER_ID, Timeout: ${SESSION_TIMEOUT}s"'

# Show session info
echo "📋 Session active. Type 'session-info' for details."
EOF

# Kill timeout process if we exit normally
trap "kill $TIMEOUT_PID 2>/dev/null || true; cleanup_session" EXIT

# Monitor ttyd process and exit if it terminates (client disconnect)
monitor_ttyd() {
    while true; do
        # Check if ttyd is still running by looking for our parent process
        if ! pgrep -f "ttyd.*7681" > /dev/null; then
            echo ""
            echo "🔌 Client disconnected - ttyd process terminated"
            cleanup_session
        fi
        sleep 2
    done
}

# Start ttyd monitor in background
monitor_ttyd &
MONITOR_PID=$!

# Enhanced cleanup to kill monitor process
cleanup_session() {
    echo ""
    echo "🧹 Session $SESSION_ID ending..."
    kill $TIMEOUT_PID $MONITOR_PID 2>/dev/null || true
    cleanup_any_existing_tokens
    echo "✅ Session cleaned up"
    echo "👋 Goodbye!"
    
    # Force exit to ensure container terminates
    exit 0
}

# Update timeout cleanup to kill monitor
timeout_cleanup() {
    echo ""
    echo "⏰ Session timeout reached after ${SESSION_TIMEOUT}s"
    kill $MONITOR_PID 2>/dev/null || true
    cleanup_session
}

# Start interactive bash with session-specific config
# Use regular bash (not exec) so we can detect when it exits
bash --rcfile /tmp/session_bashrc

# If bash exits, clean up and terminate the container
echo "🔚 Interactive session ended"
cleanup_session