#!/bin/bash

# install-gtest.sh - Script to install Google Test framework if not already installed

set -e  # Exit immediately if a command exits with non-zero status

echo "Checking for Google Test installation..."

# Check if gtest is already installed
if [ -d "/usr/include/gtest" ] || [ -d "/usr/local/include/gtest" ]; then
    echo "Google Test appears to be already installed."
else
    echo "Google Test not found. Installing..."
    
    # Create temporary directory
    TEMP_DIR=$(mktemp -d)
    cd "$TEMP_DIR"
    
    # Clone the googletest repository
    git clone https://github.com/google/googletest.git
    cd googletest
    
    # Create build directory
    mkdir -p build
    cd build
    
    # Configure, build and install
    cmake .. -DCMAKE_CXX_STANDARD=17
    make
    
    # Need sudo for system-wide installation
    echo "Installing Google Test (may require sudo)..."
    sudo make install
    
    # Clean up
    cd "$OLDPWD"
    rm -rf "$TEMP_DIR"
    
    echo "Google Test installation completed."
fi

echo "GTest setup complete."