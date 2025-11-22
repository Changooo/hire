#!/bin/bash
# Add hire/src to PATH if not already present
if ! grep -q 'export PATH="$HOME/hire/src:$PATH"' ~/.bashrc; then
    echo 'export PATH="$HOME/hire/src:$PATH"' >> ~/.bashrc
    echo "Added hire/src to PATH in ~/.bashrc"
    echo "Run 'source ~/.bashrc' to apply changes to current shell"
else
    echo "hire/src already in PATH in ~/.bashrc"
fi

# Create symlinks in /usr/local/bin for sudo access
echo ""
echo "Creating symlinks in /usr/local/bin for sudo access..."
sudo ln -sf "$HOME/hire/src/hire" /usr/local/bin/hire
sudo ln -sf "$HOME/hire/src/addagent" /usr/local/bin/addagent
sudo ln -sf "$HOME/hire/src/aid_lsm_loader" /usr/local/bin/aid_lsm_loader
sudo ln -sf "$HOME/hire/src/dump_policies" /usr/local/bin/dump_policies

if [ $? -eq 0 ]; then
    echo "✓ Symlinks created successfully"
    echo "  - hire, addagent, aid_lsm_loader, dump_policies are now available with sudo"
else
    echo "✗ Failed to create symlinks (may need sudo privileges)"
fi
