FROM ubuntu:24.04

# Avoid interactive prompts during apt operations
ENV DEBIAN_FRONTEND=noninteractive

# Install systemd, OpenSSH server, sudo, curl, iproute2
RUN apt-get update && apt-get install -y --no-install-recommends \
    systemd \
    systemd-sysv \
    openssh-server \
    sudo \
    curl \
    iproute2 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Clean up unwanted systemd units for containers
RUN cd /lib/systemd/system/sysinit.target.wants/ && rm -f $(ls | grep -v systemd-tmpfiles-setup) && \
    rm -f /lib/systemd/system/multi-user.target.wants/* \
          /etc/systemd/system/*.wants/* \
          /lib/systemd/system/local-fs.target.wants/* \
          /lib/systemd/system/sockets.target.wants/*udev* \
          /lib/systemd/system/sockets.target.wants/*initctl* \
          /lib/systemd/system/basic.target.wants/* \
          /lib/systemd/system/systemd-update-utmp*

# Configure test user 'ubuntu' with passwordless sudo (user 'ubuntu' exists by default in ubuntu 24.04)
RUN if ! id -u ubuntu >/dev/null 2>&1; then \
        useradd -rm -d /home/ubuntu -s /bin/bash -g root -G sudo -u 1000 ubuntu; \
    else \
        usermod -aG sudo ubuntu; \
    fi && \
    echo 'ubuntu ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

# Configure SSH for key-based authentication. The test session installs its own
# public key into authorized_keys (see tests/integration/conftest.py).
RUN mkdir -p /home/ubuntu/.ssh /var/run/sshd && \
    chmod 700 /home/ubuntu/.ssh && \
    chown -R ubuntu:ubuntu /home/ubuntu/.ssh

# Prevent pam_nologin from blocking non-root SSH logins during container startup
RUN sed -i '/pam_nologin.so/d' /etc/pam.d/sshd

# Enable SSH service in systemd
RUN systemctl enable ssh

STOPSIGNAL SIGRTMIN+3

CMD ["/lib/systemd/systemd"]