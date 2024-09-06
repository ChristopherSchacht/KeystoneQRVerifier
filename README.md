# KeystoneQRVerifier - Cardano

## Goal:
Creating a python application with which everyone can easily read and verify the QR codes that are being exchanged between the airgapped Keystone 3 Pro hardware wallet and the corresponding software wallet.

## current development stage
- The "Keystone-QR-Codes.py" and (previous) "Check-QR-Codes.py" create a working python GUI that lets you get either the camera or the desktop display-feed and checks for QR codes.
Every new QR code is being logged in a log-field that can be exported or cleared.

- The "keystonQRVerify.py" contains the currently working "translation" logic that translates these not human readable QR texts to Cardano transactions. Either a normal UTXO transaction or a Signnatur-Request message.

## What is missing and should be done next (_Backlog_):
- The "Keystone-QR-Codes.py" should use this decoding logic of "keystonQRVerify.py". These two files have not been merged, yet.
- Further the Decoding logic should reliably identify everything that it can't understand or that is "added" to the QR code and display that with a warning. Thus informing the user about a possible side-commmunication that might be going on.



**Attribution:**
This repo is based on the KeystoneQRVerifier which itself is based on the work of @fnord123, as the Keystone hardware wallet is simply relaunched from the Cobo Vault branding so both the code base and infrastructure are almost the same
