# Start from our Ubuntu base
FROM debian:latest

# Install SSH and sudo
RUN apt-get update && apt-get install -y \
    openssh-server \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# Create user 'luigi' with sudo access
RUN useradd -m -s /bin/bash luigi
RUN usermod -aG sudo luigi

# --- NEW: Lock the password ---
# This prevents any password-based login for this user
RUN passwd -l luigi

# --- NEW: Add your SSH Public Key ---
# Create the .ssh directory for the 'luigi' user
RUN mkdir -p /home/luigi/.ssh
RUN chown luigi:luigi /home/luigi/.ssh
RUN chmod 700 /home/luigi/.ssh

# Copy the key file you created (my_key.pub) from your build directory...
# ...and name it 'authorized_keys' inside the container
COPY id_ecdsa.pub /home/luigi/.ssh/authorized_keys

# Set the correct permissions for the key file
RUN chown luigi:luigi /home/luigi/.ssh/authorized_keys
RUN chmod 600 /home/luigi/.ssh/authorized_keys


# Append our secure settings to the end of the config file
# This overrides any defaults and enforces key-only auth
RUN echo "\n# --- Custom Secure Settings ---" >> /etc/ssh/sshd_config && \
    echo "PermitRootLogin no" >> /etc/ssh/sshd_config && \
    echo "PasswordAuthentication no" >> /etc/ssh/sshd_config && \
    echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config && \
    echo "ChallengeResponseAuthentication no" >> /etc/ssh/sshd_config

EXPOSE 22

# Start the SSH service
CMD ["/usr/sbin/sshd", "-D"]