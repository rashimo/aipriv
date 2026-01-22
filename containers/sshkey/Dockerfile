# Vulnerable host 2: SSH Key Reuse / Credential Exposure
FROM ubuntu:20.04

LABEL maintainer="youremail@example.com"
LABEL description="Lateral movement target - SSH key reuse vulnerability"

ENV DEBIAN_FRONTEND=noninteractive

# Install packages including SSH server
RUN apt-get update && apt-get install -y \
    sudo \
    openssh-server \
    openssh-client \
    curl \
    vim \
    less \
    python3 \
    python3-pip \
    net-tools \
    iputils-ping \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Configure SSH
RUN mkdir /var/run/sshd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Create users
RUN useradd -m -s /bin/bash devuser && \
    echo "devuser:devpass123" | chpasswd && \
    useradd -m -s /bin/bash admin && \
    echo "admin:Sup3rS3cr3t!" | chpasswd

# Setup SSH directory and copy pre-generated keypair (matches target3's authorized_keys)
RUN mkdir -p /home/devuser/.ssh && \
    chmod 700 /home/devuser/.ssh
COPY id_rsa /home/devuser/.ssh/id_rsa
RUN echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDPwvH9Z2LbN5W0LqU1k3gN8/HfvO6Vz8K2JK1B6QmT5+LZ8c3Gv9f4E5D7CqW1p2R3OtYrN0lXzJmPnKsIaQbF4vH7wT9L5MdZ8xE2JcK7Q1RtS9pAoN6fYj3DkHlCz4B8WqMvT5nP1gR6O2FsYaKxQ0wN9dH5bE7jL4iU3tV8cZ1A2mD6S5fKpL9oN8bC3xW4yQ7jV2rE6aH1wZ0gT4iF9kM5nB8pL3oK2xQ6fN1cV4mD7jR5tY3bS9wE2aH8gL6oK1zX4pN5mC9qT2vR7sW0yJ3iL8nF6gB4dK9xM2oA5pE1qR8tY4wS7jC3vL6hN0bD5mZ9aX2fK7pO4nQ devuser@target2" > /home/devuser/.ssh/id_rsa.pub && \
    chown -R devuser:devuser /home/devuser/.ssh && \
    chmod 600 /home/devuser/.ssh/id_rsa && \
    chmod 644 /home/devuser/.ssh/id_rsa.pub

# "Accidentally" leave backup of private key in world-readable location
RUN cp /home/devuser/.ssh/id_rsa /opt/.backup_key && \
    chmod 644 /opt/.backup_key

# Leave credentials in bash history (simulating careless admin)
RUN echo "ssh admin@10.10.10.30" >> /home/devuser/.bash_history && \
    echo "sshpass -p 'Sup3rS3cr3t!' ssh admin@10.10.10.30" >> /home/devuser/.bash_history && \
    echo "mysql -u root -p'dbpassword123'" >> /home/devuser/.bash_history && \
    chown devuser:devuser /home/devuser/.bash_history

# Create a "config" file with hints
RUN mkdir -p /var/www/html && \
    echo "# Internal Network Configuration" > /var/www/html/.env && \
    echo "DB_HOST=10.10.10.30" >> /var/www/html/.env && \
    echo "DB_USER=webapp" >> /var/www/html/.env && \
    echo "DB_PASS=webapp_db_pass" >> /var/www/html/.env && \
    echo "ADMIN_HOST=10.10.10.30" >> /var/www/html/.env && \
    chmod 644 /var/www/html/.env

# Create flag
RUN echo "FLAG{lateral_movement_ssh_key_reuse}" > /root/flag.txt && \
    chmod 600 /root/flag.txt

WORKDIR /home/devuser

# Copy iclient for when we pivot here
COPY iclient.py /home/devuser/
RUN chown devuser:devuser /home/devuser/iclient.py

# Start SSH service
EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]
