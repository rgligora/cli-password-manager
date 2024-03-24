#!/bin/bash

PYTHON_SCRIPT="./tajnik.py"


if ! python3 -c "import Crypto" &> /dev/null; then
    echo "PyCryptodome is not installed. Attempting to install..."
    pip install pycryptodome
    if [[ $? -ne 0 ]]; then
        echo "Failed to install PyCryptodome. Please install it manually and rerun the script."
        exit 1
    fi
fi

echo "TAJNIK"
echo "  _________       ___   ________ __"
echo " /_  __/   |     / / | / /  _/ //_/"
echo "  / / / /| |__  / /  |/ // // ,<"
echo " / / / ___ / /_/ / /|  // // /| |"
echo "/_/ /_/  |_\____/_/ |_/___/_/ |_|"

echo ""
python3 $PYTHON_SCRIPT -h

echo ""

echo "Pokretanje testnih primjera:"
echo ""
echo "Inicijalizacija baze: init mAsterPassword"
python3 $PYTHON_SCRIPT init mAsterPassword
echo "==========================================================================================="
echo "Pohrana para adresa, zaporka : put mAsterPassword www.fer.hr neprobojnASifrA"
python3 $PYTHON_SCRIPT put mAsterPassword www.fer.hr neprobojnASifrA
echo "==========================================================================================="
echo "Dohvacanje pohranjene zaporke za zadanu adresu : get mAsterPassword www.fer.hr"
python3 $PYTHON_SCRIPT get mAsterPassword www.fer.hr
echo "==========================================================================================="
echo "Zamijena pohranjene zaporke za zadanu adresu : put mAsterPassword www.fer.hr probojnaSifrA"
python3 $PYTHON_SCRIPT put mAsterPassword www.fer.hr probojnaSifrA
echo "==========================================================================================="
echo "Dohvacanje zamijenjene zaporke : get mAsterPassword www.fer.hr"
python3 $PYTHON_SCRIPT get mAsterPassword www.fer.hr
echo "==========================================================================================="
echo "Koristenje neispravna glavne zaporke : get wrongMasterPassword www.fer.hr"
python3 $PYTHON_SCRIPT get wrongMasterPassword www.fer.hr
echo "==========================================================================================="
echo "Dohvacanje zaporke za nepostojecu adresu : get mAsterPassword www.tel.fer.hr"
python3 $PYTHON_SCRIPT get mAsterPassword www.tel.fer.hr
echo "==========================================================================================="
echo "Dohvacanje zaporke za nepostojecu adresu : put mAsterPassword www.tel.fer.hr tel3Kom1"
python3 $PYTHON_SCRIPT put mAsterPassword www.tel.fer.hr tel3Kom1
echo "==========================================================================================="
echo "Dohvacanje zaporke za novo unesene adrese : get mAsterPassword www.tel.fer.hr"
python3 $PYTHON_SCRIPT get mAsterPassword www.tel.fer.hr
echo "==========================================================================================="




