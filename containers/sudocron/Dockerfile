# Vulnerable host 3: Weak Sudo + Cron Job Privilege Escalation
FROM ubuntu:20.04

LABEL maintainer="youremail@example.com"
LABEL description="Lateral movement target - sudo/cron privilege escalation"

ENV DEBIAN_FRONTEND=noninteractive

# Install packages including SSH server and cron
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
    cron \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Configure SSH
RUN mkdir /var/run/sshd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config

# Create users
RUN useradd -m -s /bin/bash admin && \
    echo "admin:Sup3rS3cr3t!" | chpasswd && \
    useradd -m -s /bin/bash webmaster && \
    echo "webmaster:w3bm4st3r" | chpasswd

# Setup SSH authorized_keys for admin (accepts key from target2's devuser)
RUN mkdir -p /home/admin/.ssh && \
    chmod 700 /home/admin/.ssh && \
    touch /home/admin/.ssh/authorized_keys && \
    chmod 600 /home/admin/.ssh/authorized_keys && \
    chown -R admin:admin /home/admin/.ssh

# Weak sudo configuration - admin can run vim as root (GTFOBins)
RUN echo "admin ALL=(root) NOPASSWD: /usr/bin/vim" >> /etc/sudoers && \
    echo "admin ALL=(root) NOPASSWD: /usr/bin/find" >> /etc/sudoers

# Create vulnerable cron job - writable script that runs as root
RUN mkdir -p /opt/scripts && \
    echo '#!/bin/bash' > /opt/scripts/backup.sh && \
    echo '# Backup script - runs every minute' >> /opt/scripts/backup.sh && \
    echo 'tar -czf /tmp/backup.tar.gz /var/log/*.log 2>/dev/null' >> /opt/scripts/backup.sh && \
    chmod 777 /opt/scripts/backup.sh && \
    echo "* * * * * root /opt/scripts/backup.sh" >> /etc/crontab

# Create another privesc vector - writable /etc/passwd scenario via group
RUN groupadd developers && \
    usermod -aG developers webmaster

# Leave some breadcrumbs
RUN echo "# Server Notes" > /home/admin/notes.txt && \
    echo "- Backup script at /opt/scripts/backup.sh" >> /home/admin/notes.txt && \
    echo "- Webmaster account for web deployments" >> /home/admin/notes.txt && \
    echo "- Use sudo vim for config edits" >> /home/admin/notes.txt && \
    chown admin:admin /home/admin/notes.txt

# Create internal service simulation
RUN echo "DATABASE_URL=mysql://dbadmin:Pr0dDB_P4ss@localhost/production" > /home/webmaster/.env && \
    echo "API_KEY=sk-prod-a8f3n2k5m9x1" >> /home/webmaster/.env && \
    chown webmaster:webmaster /home/webmaster/.env && \
    chmod 600 /home/webmaster/.env

# Create flags
RUN echo "FLAG{sudo_vim_gtfobins_privesc}" > /root/flag.txt && \
    chmod 600 /root/flag.txt && \
    echo "FLAG{cron_script_injection}" > /root/flag2.txt && \
    chmod 600 /root/flag2.txt

WORKDIR /home/admin

# Copy iclient for when we pivot here
COPY iclient.py /home/admin/
RUN chown admin:admin /home/admin/iclient.py

# Startup script to setup SSH keys and start services
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22

ENTRYPOINT ["/entrypoint.sh"]
