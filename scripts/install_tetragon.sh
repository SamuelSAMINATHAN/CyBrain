#!/bin/bash
# CyBrain - Tetragon Auto-Installer

echo "[*] Mise à jour du système et installation de curl..."
sudo apt update && sudo apt install curl -y

echo "[*] Téléchargement de Tetragon v1.6.0..."
curl -LO https://github.com/cilium/tetragon/releases/download/v1.6.0/tetragon-v1.6.0-amd64.tar.gz
tar -xvf tetragon-v1.6.0-amd64.tar.gz

echo "[*] Installation de Tetragon..."
cd tetragon-v1.6.0-amd64/
sudo ./install.sh

echo "[*] Démarrage du service Tetragon..."
sudo systemctl start tetragon
sudo systemctl enable tetragon

# Vérification du chemin de tetra
TETRA_BIN=$(find /home/user/tetragon-v1.6.0-amd64 -name "tetra" | head -n 1)

if [ -z "$TETRA_BIN" ]; then
    TETRA_BIN="tetra" # Fallback si déjà dans le PATH
fi

echo "[*] Application de la TracingPolicy CyBrain..."
# Utilisation de ton fichier YAML dans le repo
sudo $TETRA_BIN tracingpolicy add ../scripts/kprobe-network-process.yaml

echo "[✔] Tetragon est prêt et la politique est active."