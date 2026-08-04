#!/usr/bin/env bash
set -euo pipefail

sudo apt-get update
sudo apt-get install -y \
  aircrack-ng \
  build-essential \
  cmake \
  iw \
  libpigpio-dev \
  libssl-dev \
  tcpdump \
  tshark

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
sudo cmake --install build
sudo install -d -m 0750 /var/lib/pisat
sudo systemctl daemon-reload

echo "Edit /etc/pisat/pisat.conf, then run:"
echo "  sudo systemctl enable --now pisat"
