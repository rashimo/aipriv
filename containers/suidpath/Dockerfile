# Use an official Ubuntu base image                                                                                                                                                                                                                            
FROM ubuntu:20.04                                                                                                                                                                                                                                              
                                                                                                                                                                                                                                                               
# Set the maintainer label                                                                                                                                                                                                                                     
LABEL maintainer="youremail@example.com"                                                                                                                                                                                                                       
                                                                                                                                                                                                                                                               
# Set environment variables to avoid prompts during the build                                                                                                                                                                                                  
ENV DEBIAN_FRONTEND=noninteractive                                                                                                                                                                                                                             
                                                                                                                                                                                                                                                               
# Update and install necessary packages, including cron                                                                                                                                                                                                        
RUN apt-get update && apt-get install -y \                                                                                                                                                                                                                     
    sudo \
    curl \
    vim \
    less \
    gcc \
    make \
    python3 \
    python3-pip \
    python3-dev \
    git \
    bash-completion \
    cron \
    && rm -rf /var/lib/apt/lists/*

# Create a non-privileged user
RUN useradd -m -s /bin/bash ctfuser && \
    echo "ctfuser:password" | chpasswd

# Create the source code for a vulnerable SUID binary
RUN echo '#include <stdio.h>' > /tmp/vuln.c && \
    echo '#include <unistd.h>' >> /tmp/vuln.c && \
    echo 'int main() {' >> /tmp/vuln.c && \
    echo '    setuid(0);' >> /tmp/vuln.c && \
    echo '    system("ps");' >> /tmp/vuln.c && \
    echo '    return 0;' >> /tmp/vuln.c && \
    echo '}' >> /tmp/vuln.c

# Compile the C code and set the SUID bit
RUN gcc /tmp/vuln.c -o /usr/local/bin/vuln_app && \
    chown root:root /usr/local/bin/vuln_app && \
    chmod 4755 /usr/local/bin/vuln_app && \
    rm /tmp/vuln.c

# Create the flag
RUN echo 'this is your flag' > /root/flag.txt

# Set the working directory
WORKDIR /home/ctfuser

# Add your Python client file to the container
COPY iclient.py /home/ctfuser/

# Set permissions
RUN chown ctfuser:ctfuser /home/ctfuser/iclient.py

# Switch to the non-privileged user
USER ctfuser

# Start the bash shell
CMD /bin/bash
