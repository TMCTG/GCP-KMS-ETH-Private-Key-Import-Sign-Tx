## Ethereum Private Key Import and Signing Transactions with Google Cloud Platform Key Management Service
  
### AKA "Cloud-based hardware wallet".  
  
This script can take a given Ethereum-type private key, convert it to a PKCS#8 DER-encoded key, wrap it with a Google Cloud Platform (GCP) Key Management Service (KMS) wrapping key and import it into a GCP KMS Hardware Security Module (HSM).  
  
Then it can build a test transaction and use the GCP KMS HSM to sign it - The r, s, v & y_parity values are extracted from the signature and the reconstructed signed transaction can be broadcast from the local device.  
This is a paid service that costs about $2.65 per month to host. (Eliptic Curve key versions with protection level HSM cost $2.50 per key version per month, plus $0.15 per 10,000 operations.)  
Other cloud-based KMS providers can host Asymmetric Elliptic Curve SECP256K1 keys (Which is what Ethereum and Bitcoin private keys are), but many don't support importing Asymmetric keys by supplying your own key materials (See AWS[^1]), they require new keys to be created to be used.  
But GCP KMS allows you to import asymmetric key material[^2] to Bring Your Own Key.  

### Upload my private key to the internet, are you crazy?!
Hardware wallets are the gold standard in personal private key security. But what if you want to automate some of your regular decentralised finance (DeFi) activities like compounding or taking profit from a farm or ROI DAPP? Hardware wallets sacrifice convenience for security, and you'll still need to manually approve each transaction if you create a script that prepares transactions and prompts your hardware wallet to sign them.  
You... *could*... export your private key or pass phrase from the hardware wallet and hard code it in an automation script, but then you've circumvented the security provided by the hardware wallet and put your funds at risk. Even if you encrypt the key, at some point in your script you'll have to pass the private key as plain text to the transaction signing function. Not a great way to go, honestly.

Consider instead, hosting your private key on a reputable cloud-based HSM and signing automated transactions with **revokable credentials**. This is, in my estimation, a reasonable combination of security and convenience if you can get the key there safely. Feel free to read Google's HSM Architecture Whitepaper to get a better understanding of how they store secrets[^2].

In order to make the uploading of the key as secure (and easy) as possible, the different stages of this process are split up so that the most sensitive part of the process (Entering your private key, PCKS8 DER encoding it and wrapping it with the Import job's wrapping key) can be done offline and/or from a secure and trusted boot image such as Tails[^3].
And you'll note that all the code is on full display to be scrutinised. And please do, especially the two "step 2" functions that deal with the most sensitive part of the process.

Script steps:
1. (Online) Create a key and an Import Job and download the wrapping key
2. (Offline &/ Secure) Convert the EVM private key into DER PKCS#8 and wrap with downloaded wrapping key.
3. (Online) Upload wrapped key into GCP KMS and 'destroy' the 1st key version (pre-import) to avoid being billed for it (You are billed for each key version).
4. (Online) Test. Build a transaction, have GCP KMS sign it, then send it to the blockchain to be mined.

Test prv_key = 3cd0560f5b27591916c643a0b7aa69d03839380a738d2e912990dcc573715d2c  
Test wallet address = '0x9608C4dE7Cb6Cfd5229ac7cC701AdCE3D1c2c669'  
Feel free to use this private key/wallet as a test, it should still have gas on bsc-test and avax-test networks.  
  
There is some set up required before using this script.
Head over to GCP KMS and run through this list of prerequisites. https://cloud.google.com/kms

## Prerequisites to running this script:  

### 1. Create a Google Cloud Platform project.

### 2. To ensure the account doing the importing & signing has bare minimum permissions we need to copy and edit an existing IAM role.
   *(Google Cloud Console, under 'IAM and Admin' -> 'Roles')*
   1. Type "kms importer" to the right of 'Filter', select "Cloud KMS Importer"
   2. Click the 3 vertical dots to the right of Status: Enabled, then select "Create role from this role"
   3. Click the button '+ ADD PERMISSIONS', then to the right of 'Filter', add these extra permissions individually.
     * cloudkms.cryptoKeyVersions.create
     * cloudkms.cryptoKeyVersions.destroy
     * cloudkms.cryptoKeyVersions.list
     * cloudkms.cryptoKeys.create

### 3. Create a new service account for this project
   *(GCC, under 'IAM and Admin' -> "Service Accounts', then press the button '+ CREATE SERVICE ACCOUNT')*
   1. (Optional) Choose a 'Service account name', *e.g. 'KMS Service Account'*
   2. (Mandatory) Choose a 'Service account ID', *e.g. 'kms-service-account'*
   3. (Optional) Choose a 'Service account description', *e.g. 'Importer/Signer'*

### 4. Assign this service account two roles, the custom role created in step 2, and "Cloud KMS CryptoKey Signer/Verifier"
   *(GCC, under 'IAM and Admin' -> "IAM', then press the button '+ GRANT ACCESS')*
   1. Under 'Principals', 'New principals', start typing 'kms-service-account' (or whatever you specified in 3b) then click the correct account from the pop-up)
   2. Under 'Assign roles', 'Select a role *', start typing 'kms importer', select 'Custom Cloud KMS Importer'
   3. Press the button '+ ADD ANOTHER ROLE', then under 'Select a role', type 'signer/', select 'Cloud KMS CryptoKey Signer/Verifier'
   4. Press the button 'SAVE' at the bottom.

### 5. Create a key ring.
   *(GCC, 'Security' -> 'Key Management', then press the button ' + CREATE KEY RING')*
   1. Give the key ring a name and press the 'CREATE' button.
   2. Press the 'CANCEL' button on the 'Create key' page to go back to the key ring screen

### 6. Take note of the following fields - You'll need to enter them in the python script:
   * project_id: (Click on the project name to the left of the main search bar) Google Cloud project ID, *e.g. 'my-project'.*
   * location_id: = *(GCC->'Security'->'Key Management'->'KEY RINGS' tab)* The location of the key ring, *e.g. 'global', 'asia', 'us-east1'.*
   * key_ring_id: = *(GCC->'Security'->'Key Management'->'KEY RINGS' tab)* The name of the key ring, *e.g. 'my-key-ring'.*
   * crypto_key_id = You decide, but consider choosing a name that helps you identify the key, like an abbreviated wallet address, *e.g. '0x9608_c669'*

   *FYI, you could automate crypto_key_id in this format by determining the wallet address from the private key:  
   *(Only caveat being that you need this crypto_key_id in step 1, but you're not entering the private key until step 2. I'll let you decide whether it's worth setting manually or not)*  

```
import web3, re
print(re.sub("(^.{6})(.*)(.{4}$)", "\g<1>_\g<3>", web3.Account.privateKeyToAccount("3cd0560f5b27591916c643a0b7aa69d03839380a738d2e912990dcc573715d2c")._address))

0x9608_c669
```

### 7. Create a Key for the Service Account that will be used for authentication
   *(GCC, 'IAM and Admin', 'Service Accounts')*
   1. Under 'Actions' for your service account click the three vertical dots and choose 'Manage keys'
   2. Click 'ADD KEY', choose 'JSON' and save it somewhere safe on your PC. You''

### 8. Install python and all required modules.
   1. After installing python, install the necessary modules:  
   python should already have these native modules pre-installed: pickle codecs binascii os base64 time decimal  
   So just go ahead and add these extra ones:  
   ```
   python.exe -m pip install google-cloud-kms google-api-python-client ecdsa cryptography crcmod six web3 requests eth_account rlp Crypto
   ```
   
## That's it
Read through the code if you haven't, when you're comfortable run the script and do a test run online for all steps with the sample private key provided.
Send some transactions, and if you get comfortable enough, 
[^1]: https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys.html - "AWS: Imported key material is supported only for symmetric encryption KMS keys"
[^2]: https://cloud.google.com/kms/docs/importing-a-key#preparing_the_key
[^3]: https://cloud.google.com/docs/security/cloud-hsm-architecture
[^4]: Link to Tails: https://tails.boum.org/ Article on Tails: https://www.wired.com/2014/04/tails/
