#!/bin/bash

echo "---------------------------------------------"
echo " Installing Python 3.7 + Virtual Environment"
echo "---------------------------------------------"

sudo apt update
sudo apt install -y python3.7 python3.7-venv python3.7-dev python3-pip

echo "---------------------------------------------"
echo " Creating Virtual Environment: venv37"
echo "---------------------------------------------"

cd ~/ddgp_workspace/AlertPrioritization || exit
python3.7 -m venv venv37

# Activate venv
source venv37/bin/activate

echo "---------------------------------------------"
echo " Upgrading pip"
echo "---------------------------------------------"

pip install --upgrade pip

echo "---------------------------------------------"
echo " Installing TensorFlow 1.13.1 (CPU)"
echo "---------------------------------------------"

# TensorFlow wheel often times out → extend timeout
pip install tensorflow==1.13.1 --default-timeout=200

echo "---------------------------------------------"
echo " Fixing protobuf compatibility for TF 1.x"
echo "---------------------------------------------"

pip install protobuf==3.20.0

echo "---------------------------------------------"
echo " Installing required Python packages"
echo "---------------------------------------------"

pip install \
    numpy==1.19 \
    scipy==1.4 \
    pandas==1.1 \
    scikit-learn==0.22 \
    matplotlib==3.1 \
    imbalanced-learn==0.6 \
    tqdm \
    gym \
    scapy

echo "---------------------------------------------"
echo " Installation Complete!"
echo "---------------------------------------------"

echo "Testing TensorFlow import..."
python3.7 - << 'EOF'
import tensorflow as tf
print("TensorFlow version:", tf.__version__)
EOF

echo "---------------------------------------------"
echo " Setup environment is ready!"
echo " To activate, run:"
echo "     source ~/ddgp_workspace/AlertPrioritization/venv37/bin/activate"
echo "---------------------------------------------"

