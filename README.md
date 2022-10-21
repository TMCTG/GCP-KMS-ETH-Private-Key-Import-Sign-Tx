# Google Cloud Platform Key Management Service - Ethereum Private Key Import and Sign Transaction
Test prv_key = 3cd0560f5b27591916c643a0b7aa69d03839380a738d2e912990dcc573715d2c
Test wallet address = '0x9608C4dE7Cb6Cfd5229ac7cC701AdCE3D1c2c669'
Feel free to use this private key/wallet as a test, it should still have gas on bsc-test and avax-test networks.

https://cloud.google.com/kms
Prerequisites of using this script:

##1. Create a Google Cloud Platform project.

##2. To ensure the account doing the importing & signing has bare minimum permissions we need to copy and edit an existing IAM role.##
   ####(Google Cloud Console, under 'IAM and Admin' -> 'Roles'
   a. Type "kms importer" to the right of 'Filter', select "Cloud KMS Importer"
   b. Click the 3 vertical dots to the right of Status: Enabled, then select "Create role from this role"
   c. Click the button '+ ADD PERMISSIONS', then to the right of 'Filter', add these extra permissions individually.
       cloudkms.cryptoKeyVersions.create
       cloudkms.cryptoKeyVersions.destroy
       cloudkms.cryptoKeyVersions.list
       cloudkms.cryptoKeys.create

##3. Create a new service account for this project
   (GCC, under 'IAM and Admin' -> "Service Accounts', then press the button '+ CREATE SERVICE ACCOUNT')
   a. (Optional) Choose a 'Service account name', e.g. 'KMS Service Account'
   b. (Mandatory) Choose a 'Service account ID', e.g. 'kms-service-account'
   c. (Optional) Choose a 'Service account description', e.g. 'Importer/Signer'

##4. Assign this service account two roles, the custom role created in step 2, and "Cloud KMS CryptoKey Signer/Verifier"
   (GCC, under 'IAM and Admin' -> "IAM', then press the button '+ GRANT ACCESS')
   a. Under 'Principals', 'New principals', start typing 'kms-service-account' (or whatever you specified in 3b) then click the correct account from the pop-up)
   b. Under 'Assign roles', 'Select a role *', start typing 'kms importer', select 'Custom Cloud KMS Importer'
   c. Press the button '+ ADD ANOTHER ROLE', then under 'Select a role', type 'signer/', select 'Cloud KMS CryptoKey Signer/Verifier'
   d. Press the button 'SAVE' at the bottom.

##5. Create a key ring.
   (GCC, 'Security' -> 'Key Management', then press the button ' + CREATE KEY RING')
   a. Give the key ring a name and press the 'CREATE' button.
   b. Press the 'CANCEL' button on the 'Create key' page to go back to the key ring screen

##6. Take note of the following fields - You'll need to enter them in the python script:
   project_id: (Click on the project name to the left of the main search bar) Google Cloud project ID (e.g. 'my-project').
   location_id: = (GCC->'Security'->'Key Management'->'KEY RINGS' tab. The location of the key ring, e.g. 'global', 'asia', 'us-east1'.
   key_ring_id: = (GCC->'Security'->'Key Management'->'KEY RINGS' tab. The name of the key ring, e.g. 'my-key-ring').
   crypto_key_id = You decide, but consider choosing a name that helps you identify the key, like an abbreviated wallet address, e.g. '0x9608_c669'

   FYI, you could automate crypto_key_id in this format by determining the wallet address from the private key:
   import web3, re; print(re.sub("(^.{6})(.*)(.{4}$)", "\g<1>_\g<3>", web3.Account.privateKeyToAccount("3cd0560f5b27591916c643a0b7aa69d03839380a738d2e912990dcc573715d2c")._address))
   0x9608_c669

##7. Create a Key for the Service Account that will be used for authentication
   (GCC, 'IAM and Admin', 'Service Accounts'
   a. Under 'Actions' for your service account click the three vertical dots and choose 'Manage keys'
   b. Click 'ADD KEY', choose 'JSON' and save it somewhere safe on your PC. You''

##8. Install python and all required modules.
   a. After installing python, install the modules by entering the following:
   python.exe -m pip install google.cloud google.oauth2 pickle codecs ecdsa binascii cryptography os base64 crcmod six web3 requests.auth time decimal eth_account rlp Crypto.Hash
   python should have these pre-installed: pickle codecs binascii os base64 time decimal
   python.exe -m pip install google-cloud-kms google-api-python-client ecdsa cryptography crcmod six web3 requests eth_account rlp Crypto
