FROM ubuntu:26.04

# Avoid interactive prompts during apt operations
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    systemd \
    systemd-sysv \
    openssh-server \
    sudo \
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

# Configure test user 'ubuntu' with passwordless sudo (user 'ubuntu' exists by default in ubuntu 26.04)
RUN if ! id -u ubuntu >/dev/null 2>&1; then \
        useradd -rm -d /home/ubuntu -s /bin/bash -g root -G sudo -u 1000 ubuntu; \
    else \
        usermod -aG sudo ubuntu; \
    fi && \
    echo 'ubuntu ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

# sshd uses the stack's host key and authorizes its client key at boot.
COPY hostkey.conf /etc/ssh/sshd_config.d/10-hostkey.conf
COPY authorize-key.service /etc/systemd/system/
RUN mkdir -p /var/run/sshd && systemctl enable authorize-key ssh

# Prevent pam_nologin from blocking non-root SSH logins during container startup
RUN sed -i '/pam_nologin.so/d' /etc/pam.d/sshd

STOPSIGNAL SIGRTMIN+3

CMD ["/lib/systemd/systemd"]
