#!/bin/bash
set -x

echo "=== DEBUG WRAPPER START ==="
echo "Timestamp: $(date)"
echo "User: $(whoami)"
echo "PWD: $(pwd)"
echo "Environment:"
env | grep -E "(VAULT|API|RUST)" | head -10

echo "=== BINARY CHECK ==="
ls -la /app/hv-iota-e2e-test
file /app/hv-iota-e2e-test 2>/dev/null || echo "file command not available"

echo "=== LIBRARY CHECK ==="
ldd /app/hv-iota-e2e-test

echo "=== EXECUTION TEST ==="
echo "Running binary with full capture..."

# Capture all output
exec 2>&1
/app/hv-iota-e2e-test &
PID=$!
echo "Binary started with PID: $PID"

# Wait and check if process is still running
sleep 1
if kill -0 $PID 2>/dev/null; then
    echo "Process still running after 1 second"
    sleep 2
    if kill -0 $PID 2>/dev/null; then
        echo "Process still running after 3 seconds"
        # Let it run normally
        wait $PID
        echo "Process exited with code: $?"
    else
        echo "Process died between 1-3 seconds"
    fi
else
    echo "Process died within 1 second"
    wait $PID 2>/dev/null
    echo "Process exit code: $?"
fi

echo "=== DEBUG WRAPPER END ==="