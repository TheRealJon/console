#!/usr/bin/env bash
set -euo pipefail

CONTAINER_NAME="console-redis"
REDIS_PORT="${REDIS_PORT:-6379}"

echo "🚀 Starting Redis for OpenShift Console session testing..."

# Check if container already exists
if podman ps -a --format "{{.Names}}" | grep -q "^${CONTAINER_NAME}$"; then
    echo "📦 Container '${CONTAINER_NAME}' already exists"

    # Check if it's running
    if podman ps --format "{{.Names}}" | grep -q "^${CONTAINER_NAME}$"; then
        echo "✅ Redis is already running"
    else
        echo "▶️  Starting existing container..."
        podman start "${CONTAINER_NAME}"
        echo "✅ Redis started"
    fi
else
    echo "📦 Creating new Redis container..."
    podman run -d \
        --name "${CONTAINER_NAME}" \
        -p "${REDIS_PORT}:6379" \
        redis:7-alpine
    echo "✅ Redis created and started"
fi

# Wait for Redis to be ready
echo "⏳ Waiting for Redis to be ready..."
for i in {1..10}; do
    if podman exec "${CONTAINER_NAME}" redis-cli ping &>/dev/null; then
        echo "✅ Redis is ready!"
        break
    fi
    if [ $i -eq 10 ]; then
        echo "❌ Redis failed to start"
        exit 1
    fi
    sleep 0.5
done

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🎉 Redis is running on localhost:${REDIS_PORT}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "To enable Redis sessions in bridge, set this environment variable:"
echo ""
echo "  export BRIDGE_SESSION_STORE_TYPE=redis"
echo "  export BRIDGE_REDIS_ADDR=localhost:${REDIS_PORT}"
echo ""
echo "Then run bridge normally:"
echo ""
echo "  ./bin/bridge (with your usual flags)"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Useful commands:"
echo "  podman logs -f ${CONTAINER_NAME}          # View logs"
echo "  podman exec -it ${CONTAINER_NAME} redis-cli  # Connect to Redis CLI"
echo "  podman stop ${CONTAINER_NAME}              # Stop Redis"
echo "  podman start ${CONTAINER_NAME}             # Start Redis"
echo "  podman rm -f ${CONTAINER_NAME}             # Remove Redis"
echo ""
echo "Redis CLI commands:"
echo "  KEYS console:*                             # List all sessions"
echo "  GET console:session:token:<token>          # View session data"
echo "  TTL console:session:token:<token>          # Check expiry"
echo "  MONITOR                                    # Watch operations"
echo ""
