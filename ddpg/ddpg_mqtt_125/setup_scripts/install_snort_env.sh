#!/bin/bash
set -e

# ===========================================================
# Usage: source venv/bin/activate && bash install_snort3_venv.sh
# ===========================================================

if [ -z "$VIRTUAL_ENV" ]; then
  echo "Please activate your Python virtual environment first."
  echo "Example: source venv/bin/activate"
  exit 1
fi

INSTALL_DIR="$VIRTUAL_ENV/snort3"
echo "Installing Snort 3 into virtual environment at: $INSTALL_DIR"
echo "Virtual Environment: $VIRTUAL_ENV"
echo ""

# ===========================================================
# 1. Dependencies
# ===========================================================
echo "[1/8] Installing system dependencies..."
sudo apt update -y
sudo apt install -y \
    build-essential cmake make autoconf automake libtool pkg-config \
    libpcap-dev libpcre3-dev libdumbnet-dev \
    libluajit-5.1-dev liblzma-dev openssl libssl-dev zlib1g-dev \
    libhwloc-dev libnghttp2-dev libboost-all-dev libsqlite3-dev \
    wget curl git unzip bison flex ragel \
    libunwind-dev libmnl-dev libnetfilter-queue-dev

# ===========================================================
# 2. LibDAQ (Data Acquisition Library) - REQUIRED
# ===========================================================
echo "[2/8] Installing LibDAQ..."
cd /tmp
if [ -d "libdaq" ]; then
  rm -rf libdaq
fi
git clone https://github.com/snort3/libdaq.git
cd libdaq

# Fix timestamp issues that can cause autoconf errors
echo "  Fixing file timestamps..."
find . -exec touch {} \;

echo "  Running bootstrap..."
./bootstrap

echo "  Configuring LibDAQ for $INSTALL_DIR..."
./configure --prefix=$INSTALL_DIR

echo "  Building LibDAQ..."
make -j"$(nproc)"

echo "  Installing LibDAQ..."
make install

echo "  Updating library cache..."
sudo ldconfig

echo "LibDAQ installed successfully"
echo ""

# ===========================================================
# 3. Hyperscan (for fast pattern matching)
# ===========================================================
echo "[3/8] Installing Hyperscan..."
cd /tmp
if [ -d "hyperscan" ]; then
  rm -rf hyperscan
fi
git clone https://github.com/intel/hyperscan.git
cd hyperscan
mkdir -p build && cd build

echo "  Configuring Hyperscan..."
cmake -DCMAKE_INSTALL_PREFIX=$INSTALL_DIR -DBUILD_STATIC_AND_SHARED=1 ..

echo "  Building Hyperscan..."
make -j"$(nproc)"

echo "  Installing Hyperscan..."
make install

cd /tmp
sudo ldconfig

echo "Hyperscan installed successfully"
echo ""

# ===========================================================
# 4. FlatBuffers
# ===========================================================
echo "[4/8] Installing FlatBuffers..."
cd /tmp
if [ -d "flatbuffers" ]; then
  rm -rf flatbuffers
fi
git clone https://github.com/google/flatbuffers.git
cd flatbuffers

echo "  Configuring FlatBuffers..."
cmake -G "Unix Makefiles" -DCMAKE_INSTALL_PREFIX=$INSTALL_DIR

echo "  Building FlatBuffers..."
make -j"$(nproc)"

echo "  Installing FlatBuffers..."
make install

sudo ldconfig

echo "FlatBuffers installed successfully"
echo ""

# ===========================================================
# 5. Snort 3.x
# ===========================================================
echo "[5/8] Downloading and building Snort 3..."
cd /tmp

if [ -d "snort3-3.1.77.0" ]; then
  rm -rf snort3-3.1.77.0*
fi

echo "  Downloading Snort 3.1.77.0..."
wget -q https://github.com/snort3/snort3/archive/refs/tags/3.1.77.0.tar.gz -O snort3.tar.gz
tar -xzf snort3.tar.gz
cd snort3-3.1.77.0

# Export PKG_CONFIG_PATH so Snort can find LibDAQ and other dependencies
echo "  Setting up environment for build..."
export PKG_CONFIG_PATH="$INSTALL_DIR/lib/pkgconfig:$PKG_CONFIG_PATH"
export LD_LIBRARY_PATH="$INSTALL_DIR/lib:$LD_LIBRARY_PATH"
export PATH="$INSTALL_DIR/bin:$PATH"

echo "  Configuring Snort 3..."
./configure_cmake.sh --prefix=$INSTALL_DIR

cd build

echo "  Building Snort 3 (this may take several minutes)..."
make -j"$(nproc)"

echo "  Installing Snort 3..."
make install

sudo ldconfig

echo "Snort 3 installed successfully"
echo ""

# ===========================================================
# 6. Setup Config Directories
# ===========================================================
echo "[6/8] Setting up Snort directories..."
mkdir -p $INSTALL_DIR/etc/snort/rules
mkdir -p $INSTALL_DIR/lib/snort_dynamicrules
mkdir -p $INSTALL_DIR/var/log/snort

# Create a basic snort.lua if it doesn't exist
if [ ! -f $INSTALL_DIR/etc/snort/snort.lua ]; then
  touch $INSTALL_DIR/etc/snort/snort.lua
fi

echo "Directory structure created"
echo ""

# ===========================================================
# 7. Environment Variables
# ===========================================================
echo "[7/8] Setting up environment variables..."

# Check if already added to avoid duplicates
if ! grep -q "# Snort 3 Environment" $VIRTUAL_ENV/bin/activate; then
  echo "" >> $VIRTUAL_ENV/bin/activate
  echo "# Snort 3 Environment" >> $VIRTUAL_ENV/bin/activate
  echo "export PATH=\"$INSTALL_DIR/bin:\$PATH\"" >> $VIRTUAL_ENV/bin/activate
  echo "export SNORT_LUA_PATH=\"$INSTALL_DIR/etc/snort/snort.lua\"" >> $VIRTUAL_ENV/bin/activate
  echo "export LD_LIBRARY_PATH=\"$INSTALL_DIR/lib:\$LD_LIBRARY_PATH\"" >> $VIRTUAL_ENV/bin/activate
  echo "export PKG_CONFIG_PATH=\"$INSTALL_DIR/lib/pkgconfig:\$PKG_CONFIG_PATH\"" >> $VIRTUAL_ENV/bin/activate
  echo "Environment variables added to venv activation script"
else
  echo "Environment variables already present in activation script"
fi

# Export for current session
export PATH="$INSTALL_DIR/bin:$PATH"
export SNORT_LUA_PATH="$INSTALL_DIR/etc/snort/snort.lua"
export LD_LIBRARY_PATH="$INSTALL_DIR/lib:$LD_LIBRARY_PATH"
export PKG_CONFIG_PATH="$INSTALL_DIR/lib/pkgconfig:$PKG_CONFIG_PATH"

echo ""

# ===========================================================
# 8. Verification
# ===========================================================
echo "[8/8] Verifying installation..."
echo ""

if [ -f "$INSTALL_DIR/bin/snort" ]; then
  echo "Binary installed at: $INSTALL_DIR/bin/snort"
else
  echo "Binary not found at expected location!"
  exit 1
fi

echo ""
echo "Running snort -V:"
$INSTALL_DIR/bin/snort -V || {
    echo "Snort installation verification failed!"
    exit 1
}

echo ""
echo "=================================================="
echo "Snort 3.x installation complete!"
echo "=================================================="
echo ""
echo "Installation Summary:"
echo "  Virtual Environment: $VIRTUAL_ENV"
echo "  Snort Base Dir:      $INSTALL_DIR"
echo "  Binary:              $INSTALL_DIR/bin/snort"
echo "  Configuration:       $INSTALL_DIR/etc/snort/snort.lua"
echo "  Rules Directory:     $INSTALL_DIR/etc/snort/rules/"
echo "  Log Directory:       $INSTALL_DIR/var/log/snort/"
echo ""
echo "To use Snort, ensure your virtual environment is activated:"
echo "  source $VIRTUAL_ENV/bin/activate"
echo ""
echo "Then you can run:"
echo "  snort -V                    # Check version"
echo "  snort --daq-list           # List DAQ modules"
echo "  snort --list-modules       # List available modules"
echo ""
echo "Note: You may need to deactivate and reactivate your venv"
echo "      for the PATH changes to take effect:"
echo "  deactivate"
echo "  source $VIRTUAL_ENV/bin/activate"
echo "=================================================="
