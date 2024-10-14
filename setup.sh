#!/bin/bash

function error_exit {
    echo "$1" 1>&2
    exit 1
}

echo "============================="
echo "  Setting up APIScout..."
echo "============================="

if ! command -v go &> /dev/null; then
    error_exit "Go is not installed. Please install Go first. Visit: https://golang.org/dl/"
else
    echo "Go is installed."
fi

echo "Building the APIScout binary..."
go build APIScout.go || error_exit "Failed to build the binary."

echo "Setting permissions for APIScout..."
sudo chmod +x APIScout || error_exit "Failed to set executable permissions."

echo "Moving APIScout binary to /usr/local/bin"
sudo mv APIScout /usr/local/bin/ || error_exit "Failed to move the binary to /usr/local/bin."
APIScout -h

echo "============================="
echo "  APIScout Setup Complete!"
echo "  You can now run APIScout."
echo "============================="


