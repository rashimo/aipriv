#!/bin/bash

# Start cron service
service cron start

# Add the SSH public key from target2's devuser
# This key is pre-generated and shared between containers
cat >> /home/admin/.ssh/authorized_keys << 'EOF'
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDPwvH9Z2LbN5W0LqU1k3gN8/HfvO6Vz8K2JK1B6QmT5+LZ8c3Gv9f4E5D7CqW1p2R3OtYrN0lXzJmPnKsIaQbF4vH7wT9L5MdZ8xE2JcK7Q1RtS9pAoN6fYj3DkHlCz4B8WqMvT5nP1gR6O2FsYaKxQ0wN9dH5bE7jL4iU3tV8cZ1A2mD6S5fKpL9oN8bC3xW4yQ7jV2rE6aH1wZ0gT4iF9kM5nB8pL3oK2xQ6fN1cV4mD7jR5tY3bS9wE2aH8gL6oK1zX4pN5mC9qT2vR7sW0yJ3iL8nF6gB4dK9xM2oA5pE1qR8tY4wS7jC3vL6hN0bD5mZ9aX2fK7pO4nQ devuser@target2
EOF

chown admin:admin /home/admin/.ssh/authorized_keys

# Start SSH daemon
exec /usr/sbin/sshd -D
