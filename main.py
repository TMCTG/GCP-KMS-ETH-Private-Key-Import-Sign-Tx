# This script has four major functions:
# 1. Online: Prepare GCP platform for import (Set up keyring, create a new SECP256K1 key, create Import Job and download key)
# 2. Offline/Secure: Convert the EVM private key into DER PKCS#8 and wrap with downloaded wrapping key.
# 3. Online: Upload wrapped key into GCP KMS and 'destroy' the 1st key version (pre-import) to avoid being billed for it (You are billed for each key version).
# 4. Test. Build a transaction, have GCP KMS sign it, then send it to the blockchain to be mined.

# Sources:
# https://stackoverflow.com/questions/48101258/how-to-convert-an-ecdsa-key-to-pem-format
# https://bitcointalk.org/index.php?topic=5309706.0
# https://cloud.google.com/kms/docs/importing-a-key#kms-create-import-job-python
# https://docs.zymbit.com/tutorials/digital-wallet/ethereum-signing-example/
# https://aws.amazon.com/blogs/database/how-to-sign-ethereum-eip-1559-transactions-using-aws-kms/
# https://www.freecodecamp.org/news/how-to-create-an-ethereum-wallet-address-from-a-private-key-ae72b0eee27b/

def auth_gcp_client():
    from google.cloud import kms  # google-cloud-kms module
    # Create the client.
    from google.oauth2 import service_account  # google-api-python-client module
    credentials = service_account.Credentials.from_service_account_file('Service_Account_Key.json')
    credentials = service_account.Credentials.from_service_account_info()
    client = kms.KeyManagementServiceClient(credentials=credentials)
    return client

def step_1a_online_create_target_key(project_id, location_id, key_ring_id, crypto_key_id):
    from google.cloud import kms
    # Create the client.
    client = auth_gcp_client()

    # Build the key. For more information regarding allowed values of these fields, see:
    # https://googleapis.dev/python/cloudkms/latest/_modules/google/cloud/kms_v1/types/resources.html
    purpose = kms.CryptoKey.CryptoKeyPurpose.ASYMMETRIC_SIGN
    algorithm = kms.CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_SECP256K1_SHA256  # EC_SIGN_P256_SHA256   originally
    protection_level = kms.ProtectionLevel.HSM
    key = {
        'purpose': purpose,
        'version_template': {
            'algorithm': algorithm,
            'protection_level': protection_level
        }
    }

    # Build the parent key ring name.
    key_ring_name = client.key_ring_path(project_id, location_id, key_ring_id)

    # Call the API.
    created_key = client.create_crypto_key(request={'parent': key_ring_name, 'crypto_key_id': crypto_key_id, 'crypto_key': key})
    print('Created hsm key: {}'.format(created_key.name))


def step_1b_online_create_import_job(project_id, location_id, key_ring_id, crypto_key_id, import_job_id):
    from google.cloud import kms
    from pickle import dump
    # Source: https://cloud.google.com/kms/docs/importing-a-key#kms-create-import-job-python
    # Create a new import job in Cloud KMS and retrieve the wrapping public key.
    client = auth_gcp_client()
    # Retrieve the fully-qualified key_ring string.
    key_ring_name = client.key_ring_path(project_id, location_id, key_ring_id)

    # Set paramaters for the import job, allowed values for ImportMethod and ProtectionLevel found here:
    # https://googleapis.dev/python/cloudkms/latest/_modules/google/cloud/kms_v1/types/resources.html

    import_method = kms.ImportJob.ImportMethod.RSA_OAEP_3072_SHA1_AES_256
    protection_level = kms.ProtectionLevel.HSM
    import_job_params = {"import_method": import_method, "protection_level": protection_level}

    # Call the client to create a new import job.
    import_job = client.create_import_job({"parent": key_ring_name, "import_job_id": import_job_id, "import_job": import_job_params})
    print('Created import job: {}'.format(import_job.name))

    # Retrieve the fully-qualified crypto_key and import_job string.
    crypto_key_name = client.crypto_key_path(project_id, location_id, key_ring_id, crypto_key_id)
    import_job_name = client.import_job_path(project_id, location_id, key_ring_id, import_job_id)

    # Retrieve the public key from the import job.
    import_job = client.get_import_job(name=import_job_name)
    # import_job_pub = serialization.load_pem_public_key(bytes(import_job.public_key.pem, 'UTF-8'), backends.default_backend())
    file_contents=[crypto_key_name, import_job_name, import_job.public_key.pem]
    with open(import_job_id + ".cfg", 'wb') as fp:
        dump(file_contents, fp)
    print("Wrapping public key and import config written to file: "+import_job_id+".cfg. \nCopy this to the offline/secure machine you intend to wrap the private key with.")


def step_2_offline_convert_eth_private_key_to_der_pkcs8(eth_private_key):
    # Derive 'uncompressed public key' from private key
    from codecs import decode, encode
    from ecdsa import SECP256k1, SigningKey
    from binascii import unhexlify
    from cryptography.hazmat.primitives.serialization import load_der_private_key, Encoding, PrivateFormat, NoEncryption

    private_key_bytes = decode(eth_private_key, 'hex')
    key = SigningKey.from_string(private_key_bytes, curve=SECP256k1).verifying_key
    key_bytes = key.to_string()
    public_key = encode(key_bytes, 'hex')
    uncompressed_point_prefix = b'04'
    uncompressed_public_key = (uncompressed_point_prefix + public_key).decode()
    pre_string = "30740201010420"
    mid_string = "a00706052b8104000aa144034200"
    DER_data=unhexlify(pre_string+eth_private_key+mid_string+uncompressed_public_key)
    loaded_DER_data = load_der_private_key(DER_data, None)
    eth_private_key_der_pkcs8_bytes = loaded_DER_data.private_bytes(encoding=Encoding.DER, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption())
    return eth_private_key_der_pkcs8_bytes


def step_2b_offline_wrap_key_material(eth_private_key_der_pkcs8_bytes):
    from pickle import load
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    from os import urandom
    from cryptography.hazmat.primitives.keywrap import aes_key_wrap_with_padding
    from cryptography.hazmat.backends import default_backend
    from base64 import b64encode
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes

    with open(import_job_id + ".cfg", 'rb') as fp:
        file_contents = load(fp)
    wrapping_public_key = file_contents[2]
    import_job_pub = load_pem_public_key(bytes(wrapping_public_key, 'UTF-8'), default_backend())
    # Generate a temporary 32-byte key for AES-KWP and wrap the key material.
    formatted_key = eth_private_key_der_pkcs8_bytes
    kwp_key = urandom(32)
    wrapped_target_key = aes_key_wrap_with_padding(kwp_key, formatted_key, default_backend())
    # Wrap the KWP key using the import job key.
    wrapped_kwp_key = import_job_pub.encrypt(kwp_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(), label=None))

    with open(import_job_id+"_wrapped_target.key", "wb") as outfile:
        outfile.write(b64encode(wrapped_target_key))
    with open(import_job_id+"_wrapped_kwp.key", "wb") as outfile:
        outfile.write(b64encode(wrapped_kwp_key))
    print("Wrapped target key written to: "+import_job_id+"_wrapped_target.key")
    print("Wrapped wrapped kwp key written to: "+import_job_id+"_wrapped_kwp.key")


def step_3_online_import_wrapped_material():
    from os.path import exists
    from pickle import load
    from base64 import b64decode
    from google.cloud import kms

    if not exists(import_job_id + ".cfg"):
        print(import_job_id + ".cfg is missing. You skipped Step 1")
        return False
    if not exists(import_job_id+"_wrapped_target.key"):
        print(import_job_id+"_wrapped_target.key is missing. You skipped Step 2")
        return False
    if not exists(import_job_id+"_wrapped_kwp.key"):
        print(import_job_id+"_wrapped_kwp.key is missing. You skipped Step 2")
        return False
    with open(import_job_id + ".cfg", 'rb') as fp:
        file_contents = load(fp)
        crypto_key_name = file_contents[0]
        import_job_name = file_contents[1]
    with open(import_job_id+"_wrapped_target.key", "rb") as infile1:
        wrapped_target_key = b64decode(infile1.read())
    with open(import_job_id+"_wrapped_kwp.key", "rb") as infile2:
        wrapped_kwp_key = b64decode(infile2.read())
    client = auth_gcp_client()
    # Import the wrapped key material.
    client.import_crypto_key_version({
        "parent": crypto_key_name,
        "import_job": import_job_name,
        "algorithm": kms.CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_SECP256K1_SHA256,  # EC_SIGN_P256_SHA256,   originally
        "rsa_aes_wrapped_key": wrapped_kwp_key + wrapped_target_key,
    })
    print('Imported: {}'.format(import_job_name))

    #Destroy superfluous key versions to prevent being billed for key versions that aren't going to be used.
    key_versions = client.list_crypto_key_versions(request={"parent": crypto_key_name})._response.crypto_key_versions
    newest_key_version = max(key_versions, key=lambda ver: ver.create_time)
    if (newest_key_version.state) and ('import_job' in newest_key_version):  # state is bool True if the version is 'Enabled', and if the key 'import_job' exists it was created through this method.
        for ver in key_versions:
            if ver != newest_key_version and ver.state:  #If it's not the newest and is Enabled, destroy it.
                destroyed_version = client.destroy_crypto_key_version(request={'name': key_version_name})
                print('Destroyed key version: {}'.format(destroyed_version.name))
    return True


def convert_der_to_pem_pkcs8(eth_private_key_der_pkcs8_bytes): # Optional, if you need a PEM PKCS#8 output
    from cryptography.hazmat.primitives.serialization import load_der_private_key, PrivateFormat, Encoding, NoEncryption
    loaded_der_data = load_der_private_key(eth_private_key_der_pkcs8_bytes, None)
    eth_private_key_pem_pkcs8_bytes = loaded_der_data.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption())
    return eth_private_key_pem_pkcs8_bytes


def generate_key_material_bytes():  # (Optional) If you don't want to BYO key material you can generate one instead
    # Generate some key material in Python and format it in PKCS #8 DER as required by Google Cloud KMS.
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    key = ec.generate_private_key(ec.SECP256K1, default_backend())
    formatted_key_bytes = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    print('Generated key bytes: {}'.format(formatted_key_bytes))
    return formatted_key_bytes


def crc32c(data):
    """
    Calculates the CRC32C checksum of the provided data.
    Args:
        data: the bytes over which the checksum should be calculated.
    Returns:
        An int representing the CRC32C checksum of the provided bytes.
    """
    import crcmod
    import six
    crc32c_fun = crcmod.predefined.mkPredefinedCrcFun('crc-32c')
    return crc32c_fun(six.ensure_binary(data))


def get_w3(chain: str):
    from web3 import Web3, HTTPProvider #, IPCProvider, WebsocketProvider
    from requests.auth import HTTPBasicAuth  # Used for authenticated HTTP Providers
    from time import sleep
    import json
    chain = chain.lower()

    #Mainnets
    if chain == "bsc": w3 = Web3(HTTPProvider("https://bsc-dataseed.binance.org:443"))
    elif chain == "bsc-2":
        ankr_URL = "https://apis.ankr.com/ed34....7e0/384d9b0....5743/binance/full/main"
        ankr_project_username = 'MyProject'
        ankr_password = '$qF#....Fb2mu'
        w3 = Web3(HTTPProvider(ankr_URL, request_kwargs={'auth': HTTPBasicAuth(ankr_project_username, ankr_password)}))
    elif chain == "eth": w3 = Web3(HTTPProvider("https://rpc.ankr.com/eth"))
    elif chain == "avax": w3 = Web3(HTTPProvider("https://rpc.ankr.com/avalanche"))
    elif chain == "polygon": w3 = Web3(HTTPProvider("https://polygon-rpc.com"))

    #Testnets
    elif chain == "bsc-test": w3 = Web3(HTTPProvider("https://data-seed-prebsc-1-s1.binance.org:8545"))
    elif chain == "avax-test": w3 = Web3(HTTPProvider("https://api.avax-test.network/ext/bc/C/rpc"))
    elif chain.startswith("http"): w3 = Web3(HTTPProvider(chain))  # if the string entered starts with http, try to connect to this URL.

    # Catch-all exception
    else: raise Exception("No data for that chain in the get_w3 function. Please add it yourself")
    retries = 3
    while retries > 0:
        try:
            assert w3.isConnected()
            retries = 0
        except Exception as err:
            retries -= 1
            print(str(err) + " | Error connecting to RPC. Retrying...")
            sleep(2)
    return w3
    # - Other examples include:
    # return check_isConnected(web3.Web3(web3.Web3.IPCProvider('./path/to/geth.ipc')))
    # return check_isConnected(web3.Web3(web3.Web3.HTTPProvider('http://127.0.0.1:8545')))
    # return check_isConnected(web3.Web3(web3.Web3.WebsocketProvider('ws://127.0.0.1:8546')))
    # Authenticated example:
    # ankr_URL = "https://apis.ankr.com/ed34....7e0/384d9b0....5743/binance/full/main"
    # ankr_project_username = 'MyProject'
    # ankr_password = '$qF#....Fb2mu'
    # w3 = Web3(HTTPProvider(ankr_URL, request_kwargs={'auth': HTTPBasicAuth(ankr_project_username, ankr_password)})))


def copy_tx(tx_hash:str, w3):  # Used to copy the 'to', 'value' and 'data' fields of an existing transaction (by its hash) from the selected network.
    transaction_dict = {**(w3.eth.getTransaction(tx_hash))}
    transaction_dict['chainID'] = w3.eth.chain_id #Can't estimate gas with a ChainID, so we add this after.
    transaction_dict['data'] = transaction_dict['input']
    transaction_dict['r']=0
    transaction_dict['s']=0
    transaction_dict['v'] = transaction_dict['chainID']
    if transaction_dict['data']=="0x": transaction_dict['data']=0
    return {**{k: transaction_dict[k] for k in transaction_dict if k in ('gasPrice','gas','to','value','data','v','r','s')}}  # Return a dictionary of a subset of copied transaction fields.


def manual_tx_data(to_addr:str, function_hash:str, *args):  # This can be used for proxy contracts where the underlying contract address/function/ABI is not known. Or alternatively, use the copy_tx function
    from decimal import Decimal
    from web3 import Web3
    if len(function_hash) != 10: raise Exception("Function hash needs to be 10 characters in length")  # eg "0xba2190ac"
    data = function_hash
    for arg in args:
        if arg.startswith("0x") and len(arg)==42:  # Address type
            data += '{:0>64}'.format(arg.lower().lstrip("0x"))
        if isinstance(arg,int):  # Integer Number/Amount type (multiplied by 10^18, so enter raw numbers only, not the toWei(i,"ether") amount.
            data += '{:0>64}'.format(hex(int(Decimal(str(arg)) * 10 ** 18)).lstrip("0x"))
    return {'to': Web3.toChecksumAddress(to_addr),'data': data}  # Returns a dictionary containing to and data.


def compact_signature_test(key_version_name, w3, transaction_dict={}, tx_type=2):
    from eth_account.datastructures import SignedTransaction
    from eth_account._utils.transactions import (ChainAwareUnsignedTransaction, Transaction, UnsignedTransaction, encode_transaction, serializable_unsigned_transaction_from_dict, strip_signature)
    from rlp import encode as rlp_encode
    from ecdsa.util import sigdecode_der
    import web3
    from binascii import unhexlify, hexlify
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    from cryptography.hazmat.backends import default_backend
    from Crypto.Hash import keccak

    client = auth_gcp_client()
    public_key = client.get_public_key(request={'name': key_version_name})
    pem = public_key.pem.encode('utf-8')
    ec_key = load_pem_public_key(pem, default_backend())
    x = ec_key.public_numbers().x
    y = ec_key.public_numbers().y
    uncompressed_pubkey_hex = "04{:064x}{:064x}".format(x, y)
    wallet_address = web3.Web3.toChecksumAddress((b"0x"+hexlify(keccak.new(data=unhexlify(uncompressed_pubkey_hex[2:]), digest_bits=256).digest())[-40:]).decode())

    if 'to' not in transaction_dict: transaction_dict['to'] = web3.Web3.toChecksumAddress('0x0000000000000000000000000000000000000000')
    if 'value' not in transaction_dict: transaction_dict['value'] = 0
    if 'data' not in transaction_dict: transaction_dict['data'] = 0
    transaction_dict['from'] = wallet_address
    transaction_dict['chainID'] = w3.eth.chain_id
    transaction_dict['gasPrice'] = w3.eth.gas_price
    transaction_dict['nonce'] = w3.eth.get_transaction_count(wallet_address)
    transaction_dict['gas'] = w3.eth.estimate_gas({**{k: transaction_dict[k] for k in transaction_dict if k in ('from', 'nonce', 'to', 'data', 'value')}}) # Estimate gas with a subset of data, since gas estimates don't like certain fields to be present.
    transaction_dict['v'] = transaction_dict['chainID']
    transaction_dict['r'] = 0
    transaction_dict['s'] = 0

    if tx_type == 2: #If tx_type is set to 2, see if the chain supports Type 2 transactions otherwise fall back to type 0
        block_data = w3.eth.get_block('pending')
        if 'baseFeePerGas' in block_data:  # If this key exists then the chain supports Type 2 EIP 1559 Transactions
            baseFee = block_data.baseFeePerGas
            transaction_dict['maxFeePerGas'] = web3.gas_strategies.time_based.construct_time_based_gas_price_strategy(max_wait_seconds=30,sample_size=10)(w3, transaction_dict)
            transaction_dict['maxPriorityFeePerGas'] = transaction_dict['maxFeePerGas'] - baseFee
        else:
            tx_type = 0  # Fall back to type 0 (legacy) transaction if the chain doesn't support type 2 (EIP 1559) transactions.
    else:
        tx_type = 0  # Should be obvious, but included for readability

    # Preformat binary fields for RLP encoding
    if transaction_dict['data']==0 or transaction_dict['data']=="0x":transaction_dict['data']=b''
    if type(transaction_dict['data']) != type(b''): transaction_dict['data'] = unhexlify(transaction_dict['data'].replace('0x', ''))
    if type(transaction_dict['to']) != type(b''): transaction_dict['to'] = unhexlify(transaction_dict['to'].replace('0x', ''))

    tx_serializable=serializable_unsigned_transaction_from_dict(transaction_dict=transaction_dict) #Strip chainID & from and turn it into a class-based dictionary.
    keccak_hashed_tx = w3.keccak(rlp_encode(tx_serializable.hash())) #Hash of the RLP encoded Hash of the TX
    digest = {'sha256': bytes(keccak_hashed_tx)}
    digest_crc32c = crc32c(digest['sha256'])
    signature_response = client.asymmetric_sign(request={'name': key_version_name, 'digest': digest, 'digest_crc32c': digest_crc32c}).signature
    r, s = sigdecode_der(signature_response, None)
    for parityBit in (0, 1):
        v = transaction_dict['chainID'] * 2 + 35 + parityBit
        try:
            assert wallet_address == w3.eth.account.recoverHash(message_hash=digest['sha256'], vrs=(v, r, s))
            y_parity = bool(parityBit) #Convert to True or False
            break
        except:
            pass
    w3.eth.account.recoverHash(message_hash=bytes(keccak_hashed_tx), vrs=(v, r, s))
    encoded_signed_tx = encode_transaction(unsigned_transaction=tx_serializable,vrs=(v, r, s))
    testdiff = SignedTransaction(transaction_dict,keccak_hashed_tx, r, s, v)
    rlp_encode(tx_serializable)
    transaction_result_hash = w3.eth.sendRawTransaction(encoded_signed_tx)
    print("Transaction broadcast hash:\n%s" % hexlify(transaction_result_hash).decode("utf-8"))


def step_4_sign_and_send(key_version_name, w3, transaction_dict={}, tx_type=2):
    # w3 is the rpc endpoint returned from the get_w3 function
    # tx_type of 0 is a legacy transaction, 2 is the newer EIP 1559 type transaction.
    import web3
    import rlp
    from time import sleep
    from rlp.sedes import binary, Binary, big_endian_int, BigEndianInt, List, CountableList, boolean
    from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
    from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    from cryptography.hazmat.backends import default_backend
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from ecdsa.util import sigdecode_der
    from Crypto.Hash import keccak
    from binascii import unhexlify, hexlify

    # ------------------------------------Abstract Type Declaractions------------------------------------------------------------------------------------
    # This is a rlp serializable type for accessList param
    access_list_sede_type = CountableList(
        List([Binary.fixed_length(20, allow_empty=False), CountableList(BigEndianInt(32)), ]), )

    # ------------------------------------Class Definitions----------------------------------------------------------------------------------------------
    '''It's possible these defined classes could be replaced with imported classes from here:
        from eth_account.datastructures import SignedTransaction
        from eth_account._utils.transactions import (ChainAwareUnsignedTransaction, Transaction, UnsignedTransaction, encode_transaction, serializable_unsigned_transaction_from_dict, strip_signature)'''
    class TransactionLegacy(rlp.Serializable):
        fields = [
            ("nonce", big_endian_int),
            ("gasPrice", big_endian_int),
            ("gas", big_endian_int),
            ("to", Binary.fixed_length(20, allow_empty=True)),
            ("value", big_endian_int),
            ("data", binary),
            ("v", big_endian_int),
            ("r", big_endian_int),
            ("s", big_endian_int),
        ]

    class RawTransactionType1559(rlp.Serializable):
        transaction_type = 2

        fields = [
            ("chainId", big_endian_int),
            ("nonce", big_endian_int),
            ("maxPriorityFeePerGas", big_endian_int),
            ("maxFeePerGas", big_endian_int),
            ("gas", big_endian_int),
            ("to", Binary.fixed_length(20, allow_empty=True)),
            ("value", big_endian_int),
            ("data", binary),
            ("accessList", access_list_sede_type),
        ]

    class SignedTransactionType1559(rlp.Serializable):
        transaction_type = 2

        fields = [
            ("chainId", big_endian_int),
            ("nonce", big_endian_int),
            ("maxPriorityFeePerGas", big_endian_int),
            ("maxFeePerGas", big_endian_int),
            ("gas", big_endian_int),
            ("to", Binary.fixed_length(20, allow_empty=True)),
            ("value", big_endian_int),
            ("data", binary),
            ("accessList", access_list_sede_type),
            ("yParity", boolean),
            ("r", big_endian_int),
            ("s", big_endian_int),

        ]

    # ------------------------------------------------------------------------------------------------------------------------------------------------------
    client = auth_gcp_client()

    # Get wallet address for key

    public_key = client.get_public_key(request={'name': key_version_name})
    pem = public_key.pem.encode('utf-8')
    ec_key = load_pem_public_key(pem, default_backend())
    x = ec_key.public_numbers().x
    y = ec_key.public_numbers().y
    uncompressed_pubkey_hex = "04{:064x}{:064x}".format(x, y)
    wallet_address = web3.Web3.toChecksumAddress((b"0x"+hexlify(keccak.new(data=unhexlify(uncompressed_pubkey_hex[2:]), digest_bits=256).digest())[-40:]).decode())

    # Middleware is used for both w3.eth.get_block('pending') and web3.gas_strategies.time_based...
    from web3.gas_strategies.time_based import fast_gas_price_strategy, slow_gas_price_strategy, medium_gas_price_strategy
    from web3.middleware import geth_poa_middleware
    w3.middleware_onion.inject(geth_poa_middleware, layer=0)

    print("Native coin balance: " + str(web3.Web3.fromWei(w3.eth.getBalance(wallet_address), "ether")))  # Get ETH/BNB/AVAX/Matic Balance

    # Construct a basic transaction then update gas, gasPrice, nonce and chainID.
    if 'to' not in transaction_dict: transaction_dict['to'] = web3.Web3.toChecksumAddress('0x0000000000000000000000000000000000000000')
    if 'value' not in transaction_dict: transaction_dict['value'] = 0
    if 'data' not in transaction_dict: transaction_dict['data'] = 0
    transaction_dict['from'] = wallet_address
    transaction_dict['chainId'] = w3.eth.chain_id
    transaction_dict['nonce'] = w3.eth.get_transaction_count(wallet_address)
    if 'gas' not in transaction_dict: transaction_dict['gas'] = w3.eth.estimate_gas({**{k: transaction_dict[k] for k in transaction_dict if k in ('from', 'nonce', 'to', 'data', 'value')}})  # Estimate gas with a subset of data, since gas estimates don't like certain fields to be present.
    else: transaction_dict['gas'] = max(transaction_dict['gas'],w3.eth.estimate_gas({**{k: transaction_dict[k] for k in transaction_dict if k in ('from', 'nonce', 'to', 'data', 'value')}}))  # Use the higher amount between existing and new estimate.
    transaction_dict['v'] = transaction_dict['chainId']
    transaction_dict['r'] = 0
    transaction_dict['s'] = 0

    # Determine the true tx type and gasPrice.
    if tx_type == 2: #If tx_type is set to 2, see if the chain supports Type 2 transactions otherwise fall back to type 0
        block_data = w3.eth.get_block('pending')
        if 'baseFeePerGas' in block_data:  # If this key exists then the chain supports Type 2 EIP 1559 Transactions
            baseFee = block_data.baseFeePerGas
            transaction_dict['maxFeePerGas'] = web3.gas_strategies.time_based.construct_time_based_gas_price_strategy(max_wait_seconds=30,sample_size=20)(w3, transaction_dict)
            transaction_dict['maxPriorityFeePerGas'] = transaction_dict['maxFeePerGas'] - baseFee
            transaction_dict['accessList'] = []
        else:
            tx_type = 0  # Fall back to type 0 (legacy) transaction if the chain doesn't support type 2 (EIP 1559) transactions.
    else:
        tx_type = 0  # Should be obvious, but included for readability
    if tx_type==0:
        if 'gasPrice' not in transaction_dict: transaction_dict['gasPrice'] = w3.eth.gas_price  # If tx doesn't have a gasPrice, use the w3.eth.gas_price
        else: transaction_dict['gasPrice'] = max(
                transaction_dict['gasPrice'],
                w3.eth.gas_price,
                web3.gas_strategies.time_based.construct_time_based_gas_price_strategy(max_wait_seconds=30,sample_size=10)(w3, transaction_dict))  # Use the higher amount between existing, w3.eth.gas_price, and the 30 second confirmation estimate.

    # Preformat binary fields for RLP encoding
    if transaction_dict['data']==0 or transaction_dict['data']=="0x":transaction_dict['data']=b''
    if type(transaction_dict['data']) != type(b''): transaction_dict['data'] = unhexlify(transaction_dict['data'].replace('0x', ''))
    if type(transaction_dict['to']) != type(b''): transaction_dict['to'] = unhexlify(transaction_dict['to'].replace('0x', ''))

    # Arrange into an ordered dictionary

    if tx_type==2:
        '''transaction_1559 = RawTransactionType1559(chainId=transaction_dict['chainID'], nonce=transaction_dict['nonce'],
                                                  maxPriorityFeePerGas=transaction_dict['maxPriorityFeePerGas'],
                                                  maxFeePerGas=transaction_dict['maxFeePerGas'],
                                                  gas=transaction_dict['gas'],
                                                  to=transaction_dict['to'], value=transaction_dict['value'],
                                                  data=transaction_dict['data'], accessList=transaction_dict['accessList'])'''
        transaction_1559 = RawTransactionType1559(**{k: transaction_dict[k] for k in transaction_dict if k in RawTransactionType1559._meta.field_names})  # Short-hand of the above
        encoded_transaction = bytes([2]) + rlp.encode(transaction_1559)  # RLP encode the transaction. Eip-1559 transaction have type_id of "2" so 0x02 is added to the front of the payload.
    else:
        '''transaction_legacy = TransactionLegacy(nonce=transaction_dict['nonce'], gasPrice=transaction_dict['gasPrice'],
                                               gas=transaction_dict['gas'],
                                               to=transaction_dict['to'], value=transaction_dict['value'],
                                               data=transaction_dict['data'], v=transaction_dict['chainID'], r=0, s=0)'''
        transaction_legacy = TransactionLegacy(**{k: transaction_dict[k] for k in transaction_dict if k in TransactionLegacy._meta.field_names})  # Short-hand of the above
        encoded_transaction = rlp.encode(transaction_legacy)  # RLP encode the transaction
    print("encoded transaction: %s" % hexlify(encoded_transaction).decode("utf-8"))

    # Per Ethereum standards, Keccak hash rlp encoded transaction
    keccak_hash = keccak.new(digest_bits=256)
    keccak_hash.update(encoded_transaction)
    print("keccak_hash: %s" % keccak_hash.hexdigest())
    digest = {'sha256': keccak_hash.digest()}
    digest_crc32c = crc32c(digest['sha256'])

    # Sign the transaction with GCP KMS
    sign_response = client.asymmetric_sign(request={'name': key_version_name, 'digest': digest, 'digest_crc32c': digest_crc32c})
    signature = sign_response.signature
    try:
        hash_algo = hashes.SHA256()
        ec_key.verify(signature, keccak_hash.digest(), ECDSA((Prehashed(hash_algo))))
        print('Signature verified')
    except InvalidSignature:
        print('Signature failed to verify')

    # Initially the value of v is the chainID, now we need to reassign it according to EIP 155 to prevent replay attacks.
    # Signature consists of a R, S, V
    # GCP KMS returns a "normalized" or "lower-S form" DER encoded signature. We need to extract r & s from it.
    r, s = sigdecode_der(signature, None)
    # From EIP 155, V = chainId * 2 + 35 + recovery_id of public key.
    for parityBit in (0, 1):
        v = transaction_dict['chainId'] * 2 + 35 + parityBit
        try:
            assert wallet_address == w3.eth.account.recoverHash(message_hash=keccak_hash.digest(), vrs=(v, r, s))
            y_parity = bool(parityBit) #Convert to True or False
            break
        except:
            pass

    # We now have the signature, r, s, v & y_parity
    print("ECDSA Signature: %s" % signature)
    print("ECDSA Sig Length: %s" % len(signature))
    print("ECDSA Sig Y Parity: %s" % y_parity)
    print("R: %s" % r)
    print("S: %s" % s)
    print("V: %s" % v)

        # RLP encode the transaction along with the full signature
    if tx_type==0:
        '''signed_transaction_legacy = TransactionLegacy(transaction_legacy.nonce, transaction_legacy.gasPrice,
                                               transaction_legacy.gas, transaction_legacy.to, transaction_legacy.value,
                                               transaction_legacy.data, v, r, s)'''
        signed_transaction_legacy = TransactionLegacy(**{**{k: transaction_dict[k] for k in transaction_dict if k in TransactionLegacy._meta.field_names},'v': v, 'r': r,'s': s})  # Shorthand of the above
        encoded_transaction = rlp.encode(signed_transaction_legacy)

    if tx_type==2:
        '''signed_transaction_1559 = SignedTransactionType1559(transaction_1559.chainId, transaction_1559.nonce,
                                                       transaction_1559.maxPriorityFeePerGas, transaction_1559.maxFeePerGas,
                                                       transaction_1559.gas, transaction_1559.to, transaction_1559.value,
                                                       transaction_1559.data, transaction_1559.accessList, y_parity, r, s)'''
        signed_transaction_1559 = SignedTransactionType1559(**{**{k: transaction_dict[k] for k in transaction_dict if k in SignedTransactionType1559._meta.field_names},'yParity': y_parity, 'r': r,'s': s})  # Shorthand of the above
        encoded_transaction = bytes([2]) + rlp.encode(signed_transaction_1559)  # Add 0x02 to the front for type 2 transactions
    print("encoded signed transaction: %s" % hexlify(encoded_transaction).decode("utf-8"))
    # send raw transaction
    transaction_result_hash = w3.eth.sendRawTransaction(encoded_transaction)
    print("Transaction broadcast hash: 0x%s" % hexlify(transaction_result_hash).decode("utf-8"))

    wait_time=15
    pending_found=False
    latest_found=False
    while wait_time>0 and not latest_found:
        if not pending_found:
            pending_data = w3.eth.get_block('pending') # See which transactions are pending.
            if transaction_result_hash in pending_data.transactions:
                print("Transaction found in 'pending' block #%s" % pending_data.number)
                pending_found = True
            sleep(2.5)
            wait_time -= 2.5
        if not latest_found:
            latest_data = w3.eth.get_block('latest') # See which transactions have been mined.
            if transaction_result_hash in latest_data.transactions:
                print("Success! Tx found in 'latest' block #%s" % latest_data.number)
                latest_found = True
                break
            sleep(2.5)
            wait_time -= 2.5
    if latest_found or wait_time <= 0:
        try:
            tx_receipt = w3.eth.getTransactionReceipt(hexlify(transaction_result_hash).decode("utf-8"))
            current_block = w3.eth.block_number
            if current_block >= tx_receipt.blockNumber:
                print("Success! Tx was included in block #%s" % tx_receipt.blockNumber + ", current block is #%s" % current_block)
        except Exception as err:
            print(err)
            print("Couldn't find the transaction, please use a chain explorer to search for it")
    input("Press ENTER to continue:")
    # ----------

if __name__ == "__main__":
    project_id = "my-project"  # project_id (string): Google Cloud project ID (e.g. 'my-project').
    location_id = "asia"  # location_id (string): Cloud KMS location (e.g. 'us-east1').
    key_ring_id = "my-key-ring"  # key_ring_id (string): ID of the Cloud KMS key ring (e.g. 'my-key-ring').
    crypto_key_id = "0x9608_c669"  # "TestECKey"  # crypto_key_id (string): ID of the key to import (e.g. 'my-asymmetric-signing-key').

    import_job_id = crypto_key_id+"_Import"  # import_job_id (string): ID of the import job (e.g. 'my-import-job').
    crypto_key_version_id = "2"  # crypto_key_version_id. Assumes you're going to sign with the 2nd imported version.

    ans = True
    while ans:
        print("Make sure these values remain the same throughout all steps for each key to be imported/tested:\n  project_id = "+project_id+"\n  location_id = "+location_id+"\n  key_ring_id = "+key_ring_id+"\n  import_job_id = "+import_job_id+"\n  crypto_key_id = "+crypto_key_id)  # +"\n  crypto_key_version_id = "+crypto_key_version_id)
        print("""
          1. (Online) Create a new GCP KMS Import Job and retrieve the wrapping public key
          2. (Offline/Secure) Convert an ETH Private key to DER-encoded PKCS8, then wrap with the GCP KMS Import Job's public key or save as-is.
          3. (Online) Complete the GCP import process
          4. (Online) Sign and send a test transaction (Testnet/Mainnet options)
          Q. Quit
        """)
        ans = input("What would you like to do? ")
        if ans == "1":
            print("\n1. (Online) Create GCP Import Job and get wrapping key")
            # create the Import job and get the returned data
            #step_1a_online_create_target_key(project_id, location_id, key_ring_id, crypto_key_id)
            step_1b_online_create_import_job(project_id, location_id, key_ring_id, crypto_key_id, import_job_id)
            ans = True
        elif ans == "2":
            print("\n2. (Offline/Secure) Convert an ETH Private key to a DER PKCS8")
            print("""WARNING: You will now be required to enter the private key of your wallet.
              Ensure that you have read this open-source code, particularly the '(Offline/Secure)' function that deals with converting and wrapping your private key.
              Be aware that until your private key is wrapped with the Import Job's public key, it may be readable and vulnerable to other processes, malicious or otherwise.
              Hence why it is suggested to do Step 2 on an offline and/or secure machine/boot image such as Tails.
              Also try the whole process with a throwaway private key first.
              Proceed only after reading, acknowledging, and agreeing that you take full responsibility for the security of your private key and any loss resulting from it being compromised\n""")
            eth_private_key = input("Enter your private key:")
            eth_private_key_der_pkcs8_bytes = step_2_offline_convert_eth_private_key_to_der_pkcs8(eth_private_key)
            print("""Private key has been converted, but has not been saved yet. Options are:
              A. Wrap the private key with the GCP Import Job's public key and save to disk. (Recommended)
              B. Save as an unencrypted DER-encoded PKCS#8 file.
              C. Save as an unencrypted PEM-encoded PKCS#8 file.
              X. Go back and don't save""")
            ans2 = input("What would you like to do?").lower()
            if ans2 == "a":
                print("\nA. Wrap the private key with the GCP KMS Import Job's public key and save to disk. (Recommended)")
                step_2b_offline_wrap_key_material(eth_private_key_der_pkcs8_bytes)
            elif ans2 == "b":
                print("B. Save as an unencrypted DER-encoded PKCS#8 file.")
                with open("eth_private_key_der_pkcs8.key", "wb") as outfile:
                    outfile.write(eth_private_key_der_pkcs8_bytes)
                    print("Key written to: eth_private_key_der_pkcs8.key")
                ans="q"  # Quit
            elif ans2 == "c":
                print("C. Save as an unencrypted PEM-encoded PKCS#8 file.")
                with open("eth_private_key_pem_pkcs8.key", "wb") as outfile:
                    outfile.write(convert_der_to_pem_pkcs8(eth_private_key_der_pkcs8_bytes))
                    print("Key written to: eth_private_key_pem_pkcs8.key")
                answ="q"  # Quit
            elif ans2 == "x":
                print("X. Go back and don't save")
                ans=True  # Go back to the main menu
        elif ans == "3":
            print("\n3. (Online) Complete the GCP import process")
            response = step_3_online_import_wrapped_material()
            if response == True: ans="q"  # Quit
            if response == False: ans=True  # Go back to the main menu
        elif ans == "4":
            client = auth_gcp_client()
            key_version_name = client.crypto_key_version_path(project_id, location_id, key_ring_id, crypto_key_id, crypto_key_version_id)
            print("""\n4. (Online) Sign and send a test transaction (Testnet/Mainnet options)
              Which chain do you want to use? (Remember to claim some gas from a testnet faucet first)
              "bsc-test" - Binance Smart Chain Testnet (Recommended)
              "avax-test" - Avalanche C-Chain Fuji Testnet
              "bsc" - Binance Smart Chain Mainnet
              "avax" - Avalanche C-Chain Mainnet
               or enter a custom RPC-url starting with http/https.
              X. Go back and don't save""")
            ans_chain = input("What would you like to do? ").lower()
            if ans_chain == "x":
                print("X. Go back and don't save")
                ans=True  # Go back to the main menu
            else:
                w3 = get_w3(ans_chain)
                print("""Enter a transaction hash from this network to 'copy' and retransmit.
                  Or leave this blank and press ENTER to send a small transaction to the 0x00..00 burn address instead (Recommended)
                  Note. After this, a transaction will be sent without any further user input""")
                ans_copy_tx = input("Enter TX hash or leave blank: ")
                if ans_copy_tx == "":
                    step_4_sign_and_send(key_version_name,w3)
                else:
                    copied_tx = copy_tx(ans_copy_tx,w3)
                    step_4_sign_and_send(key_version_name,w3,copied_tx,2)
            ans = True
        elif ans.lower() == "q":
            print("\n Quitting")
            break
        elif ans != "":
            print("\n Not Valid Choice Try again")
