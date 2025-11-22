#!/bin/bash
# Add hire/src to PATH if not already present
if ! grep -q 'export PATH="$HOME/hire/src:$PATH"' ~/.bashrc; then
    echo 'export PATH="$HOME/hire/src:$PATH"' >> ~/.bashrc
    echo "Added hire/src to PATH in ~/.bashrc"
    echo "Run 'source ~/.bashrc' to apply changes to current shell"
else
    echo "hire/src already in PATH in ~/.bashrc"
fi
