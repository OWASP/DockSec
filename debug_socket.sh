#!/bin/bash
echo "User ID: $(id)"
echo "Socket path: $DOCKER_HOST"
echo "Directory listing of /var/run:"
ls -la /var/run
echo "Socket info:"
ls -la /var/run/docker.sock
echo "Testing docker connection:"
docker ps
