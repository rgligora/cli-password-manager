#!/bin/bash

PYTHON_SCRIPT="./tajnik.py"

#Funkcionalnosti programa se lako mogu testirati pokretanjem ove skripte. 
#Skripta ce provjeriti postoji li PyCryptodome biblioteka na sustavu i instalira ju ako je potrebno
#Program podrzava obradu ulaznih argumenata  te prihvaca -h zastavicu kojom se dobivaju informacije o koristenju programa
#Nakon instalacije PyCryptodome, skripta izvršava niz testova koji pokrivaju osnovne funkcionalnosti programa ('init', 'put', 'get'), kao i naprednije slučajeve poput obrade pogrešaka i provjere integriteta podataka
#Neki od testova testiraju obradu iznimki u slucaju krive lozinke ili detekcije narusenja integriteta te u slucaju unosa adrese za koju ne postoji unos 



if ! python3 -c "import Crypto" &> /dev/null; then

    echo "PyCryptodome is not installed. Installing"
    pip install pycryptodome
    if [[ $? -ne 0 ]]; then
        echo "PyCryptodome installation failed."
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




