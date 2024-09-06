# KeystoneQRVerifier - Cardano

<img width="1436" alt="image" src="https://github.com/user-attachments/assets/db039f11-cd9d-4021-8dbb-736e69c0d41e">


## Description:
A python application with which everyone can easily read and verify the QR codes that are being exchanged between the airgapped Keystone 3 Pro hardware wallet and the corresponding software wallet.

## current version
- The "Keystone-QR-Codes.py" creates a working python GUI that displays the camera and desktop feed and checks for QR codes.
Every new QR code is being logged in a log-field that can be exported or cleared.
- The QR Code is being translated into human readable Cardano transaction / signing information.

## What is missing and should be done next (_Backlog_):
- The Decoding logic should reliably identify everything of the QR Code that it can't understand or that is "added" to the QR code and display that with a warning. Thus informing the user about a possible side-commmunication that might be going on.
- It has only been tested on the most common Cardano transactions. More exotic ones and even other chains could be added.
- It has only been tested so far on MacOS 14.6.1 with M2 processor. 



**Attribution:**
This repo is based on the KeystoneQRVerifier which itself is based on the work of @fnord123, as the Keystone hardware wallet is simply relaunched from the Cobo Vault branding so both the code base and infrastructure are almost the same
