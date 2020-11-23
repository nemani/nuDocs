import fire
import datetime
import sys
import json
import os
import shutil
import maya
import traceback
import msgpack
import ipfshttpclient
import yagmail
import hashlib

import keyvalue
from timeit import default_timer as timer
from umbral.keys import UmbralPublicKey, UmbralPrivateKey

from nucypher.characters.lawful import Bob, Ursula, Enrico
from nucypher.config.characters import AliceConfiguration
from nucypher.config.constants import TEMPORARY_DOMAIN
from nucypher.crypto.kits import UmbralMessageKit
from nucypher.crypto.powers import DecryptingPower, SigningPower
from nucypher.network.middleware import RestMiddleware
from nucypher.datastore.keypairs import DecryptingKeypair, SigningKeypair


def check_or_create(target_paths):
    for target_path in target_paths:
        if not os.path.exists(target_path):
            try:
                os.makedirs(target_path)
            except OSError as exc: # Guard against race condition
                if exc.errno != errno.EEXIST:
                    raise

class nuCLI(object):
    """A simple nuCLI class having all nuCypher capabilities"""

    def __init__(self):
        '''Configuring local node'''
        # can be initialized based on inputs, but let's keep it like this for easy testing for now
        self.SEEDNODE_URI = "localhost:11500"
        
        self.CONF_DIR = os.path.join('.', 'config')
        self.ALICE_DIR = os.path.join(self.CONF_DIR, 'alice')
        self.BOB_DIR = os.path.join(self.CONF_DIR, 'bob')
        self.email_file = os.path.join(self.ALICE_DIR, 'email')
        
        try:
            with open(self.email_file) as f:
                self.email = f.read()
        except:
            pass

        check_or_create([self.CONF_DIR, self.ALICE_DIR, self.BOB_DIR])

        # Creating ipfs api object
        self.api = ipfshttpclient.connect('/dns/localhost/tcp/5001/http')
        self.email_app_pass = '' # https://support.google.com/mail/?p=BadCredentials

        self.POLICY_FILENAME = "policy-metadata.json"
        self.passphrase = "TEST_ALICIA_INSECURE_DEVELOPMENT_PASSWORD"
        
        self.PRIVATE_JSON = os.path.join(self.BOB_DIR, 'private.json')
        self.ALICE_JSON = os.path.join(self.ALICE_DIR, 'alice.config.json')
        self.HASHES_LIST = os.path.join(self.ALICE_DIR, 'hashes-list.json')


    def initialize(self, email):
        '''Initializing stuff, generating key pair'''
        with open(self.email_file, "w") as f:
            f.write(email)
        ############################
        # Initializing Alice
        ursula = Ursula.from_seed_and_stake_info(seed_uri=self.SEEDNODE_URI,
                                            federated_only=True,
                                            minimum_stake=0)

        alice_config = AliceConfiguration(
            config_root=os.path.join(self.ALICE_DIR),
            domains={TEMPORARY_DOMAIN},
            known_nodes={ursula},
            start_learning_now=False,
            federated_only=True,
            learn_on_same_thread=True,
        )

        alice_config.initialize(password=self.passphrase)
        alice_config.keyring.unlock(password=self.passphrase)
        
        # We will save Alicia's config to a file for later use
        alice_config_file = alice_config.to_configuration_file()
        
        with open(self.ALICE_JSON, 'w') as f:
            f.write(open(alice_config_file).read())
        
        alicia = alice_config.produce()
        
        # Let's get to learn about the NuCypher network
        alicia.start_learning_loop(now=True)

        ##############################
        # Initializing Bob
        if not os.path.isfile(self.PRIVATE_JSON):
            enc_privkey = UmbralPrivateKey.gen_key()
            sig_privkey = UmbralPrivateKey.gen_key()

            privkeys = {
                'enc': enc_privkey.to_bytes().hex(),
                'sig': sig_privkey.to_bytes().hex(),
            }

            with open(self.PRIVATE_JSON, 'w') as f:
                json.dump(privkeys, f)

            enc_pubkey = enc_privkey.get_pubkey()
            sig_pubkey = sig_privkey.get_pubkey()
            pubkeys = {
                'enc': enc_pubkey.to_bytes().hex(),
                'sig': sig_pubkey.to_bytes().hex()
            }

            keyvalue.set_value(email, pubkeys)

    def get_bob(self):
        # Getting private keys
        ursula = Ursula.from_seed_and_stake_info(seed_uri=self.SEEDNODE_URI,
                                    federated_only=True,
                                    minimum_stake=0)

        with open(self.PRIVATE_JSON) as f:
            stored_keys = json.load(f)
        privkeys = dict()
        for key_type, key_str in stored_keys.items():
            privkeys[key_type] = UmbralPrivateKey.from_bytes(bytes.fromhex(key_str))

        bob_enc_keypair = DecryptingKeypair(private_key=privkeys["enc"])
        bob_sig_keypair = SigningKeypair(private_key=privkeys["sig"])
        enc_power = DecryptingPower(keypair=bob_enc_keypair)
        sig_power = SigningPower(keypair=bob_sig_keypair)
        power_ups = [enc_power, sig_power]

        bob = Bob(
            domains={TEMPORARY_DOMAIN},
            federated_only=True,
            crypto_power_ups=power_ups,
            start_learning_now=True,
            abort_on_learning_error=True,
            known_nodes=[ursula],
            save_metadata=False,
            network_middleware=RestMiddleware(),
        )
        return bob

    def get_policy_pubkey(self, label):
        '''
        Alicia can create the public key associated to the policy label,
        even before creating any associated policy
        '''
        alice = self.get_alice()
        label = label.encode()
        print(alice)
        policy_pubkey = alice.get_policy_encrypting_key_from_label(label)
        return policy_pubkey


    def get_alice(self):
        '''Get Alice actor'''
        ursula = Ursula.from_seed_and_stake_info(seed_uri=self.SEEDNODE_URI,
                                            federated_only=True,
                                            minimum_stake=0)
        # A new Alice is restored from the configuration file
        new_alice_config = AliceConfiguration.from_configuration_file(
            filepath=self.ALICE_JSON,
            domains={TEMPORARY_DOMAIN},
            known_nodes={ursula},
            start_learning_now=False,
            federated_only=True,
            learn_on_same_thread=True,
        )

        # Alice unlocks her restored keyring from disk
        new_alice_config.attach_keyring()
        new_alice_config.keyring.unlock(password=self.passphrase)
        new_alice = new_alice_config()
        new_alice.start_learning_loop(now=True)

        return new_alice

    def encrypt(self, label, dir_path):
        '''Encrypting a full folder with files and uploading it to ipfs'''
        policy_pubkey = self.get_policy_pubkey(label)
        data_source = Enrico(policy_encrypting_key=policy_pubkey)
        data_source_public_key = bytes(data_source.stamp)
        
        try:
            with open(self.HASHES_LIST, "r") as f:
                hashes = json.load(f)
        except:
            hashes = {}
        
        # print(hashes)
        
        file_paths = os.scandir(dir_path)
        for file_path in file_paths:
            print(f"current: {file_path}\n\n")

            with open(file_path, "rb") as f:
                plaintext = f.read()

            md5 = hashlib.md5(plaintext).hexdigest()
            if md5 in hashes:
                print("Unchanged file: Skipping!\n\n")
                continue

            ciphertext, signature = data_source.encrypt_message(plaintext)
        
            # print("Signature", signature)
            data = {
                'file_name': file_path.name,
                'file_data': ciphertext.to_bytes(),
                'data_source': data_source_public_key
            }

            enc_file = os.path.join(self.CONF_DIR, file_path.name + '_encrypted')
            with open(enc_file, "wb") as f:
                msgpack.dump(data, f, use_bin_type=True)
        
            ipfsReq = self.api.add(enc_file)
            ipfsHash = ipfsReq['Hash']
            hashes[md5] = ipfsHash
        
        with open(self.HASHES_LIST, "w") as f:
            json.dump(hashes, f)

        print("MD5 & IPFS hash for files: ")
        return hashes


    def share(self, label, email):
        '''
        Alicia creates a policy granting access to Bob.
        The policy is sent to the NuCypher network and bob recieves an email with policy info.
        '''
        bob_pubkeys = keyvalue.get_value(email)
        privkeys = None
        if not bob_pubkeys:
            enc_privkey = UmbralPrivateKey.gen_key()
            sig_privkey = UmbralPrivateKey.gen_key()
            privkeys = {
                'enc': enc_privkey.to_bytes().hex(),
                'sig': sig_privkey.to_bytes().hex(),
            }

            bob_pubkeys = {
                'enc': enc_privkey.get_pubkey().to_bytes().hex(),
                'sig': sig_privkey.get_pubkey().to_bytes().hex()
            }

            keyvalue.set_value(email, bob_pubkeys)

        
        pubkeys = {
            'enc': UmbralPublicKey.from_bytes(bytes.fromhex(bob_pubkeys['enc'])),
            'sig': UmbralPublicKey.from_bytes(bytes.fromhex(bob_pubkeys['sig']))
        }

        with open(self.HASHES_LIST, "r") as f:
            ipfsHashes = json.load(f)
        
        alicia = self.get_alice()
        label = label.encode()
        # We create a view of the Bob who's going to be granted access.
        active_listener = Bob.from_public_keys(verifying_key=pubkeys['sig'],
                                            encrypting_key=pubkeys['enc'],
                                            federated_only=True)
        print("Creating access policy for the Listener...")
        # Policy expiration date
        policy_end_datetime = maya.now() + datetime.timedelta(days=1)
        # m-out-of-n: This means Alicia splits the re-encryption key in 2 pieces and
        #              she requires Bob to seek collaboration of at least 1 Ursulas
        m, n = 1, 2

        policy = alicia.grant(bob=active_listener,
                            label=label,
                            m=m,
                            n=n,
                            expiration=policy_end_datetime)
        
        data = {
                "policy_pubkey": policy.public_key.to_bytes().hex(),
                "alice_sig_pubkey": bytes(alicia.stamp).hex(),
                "label": label.decode(),
                "ipfsHashes": ipfsHashes,
            }
        
        if privkeys:
            data["privkeys"] = privkeys
            
        self.email_app_pass = os.environ.get("GMAIL_PASSWORD")
        yag = yagmail.SMTP(self.email, self.email_app_pass)
        contents = [
            "Hey there!", "I am happy to give you access to my files for the next 24hrs",
            "These are the things you would require to access the attatched files, "
        ]

        with open('details.json',"w") as f:
            json.dump(data, f)

        print(contents)
        yag.send(email, 'Giving Access to ' + str(label), contents, attachments=["details.json"])

    def fetch(self, details_file, target_path):
        '''Fetches data from ipfs and then decrypts it'''
        # Join Policy
        with open(details_file, "r") as f:
            data = json.load(f)

        if "privkeys" in data:
            with open(self.PRIVATE_JSON, "w") as f:
                json.dump(data["privkeys"], f)
        
        bob = self.get_bob()
        
        policy_pubkey = UmbralPublicKey.from_bytes(bytes.fromhex(data["policy_pubkey"]))
        alices_sig_pubkey = UmbralPublicKey.from_bytes(bytes.fromhex(data["alice_sig_pubkey"]))
        label = data["label"].encode()

        print("Joins policy for label '{}'".format(label.decode("utf-8")))
        bob.join_policy(label, alices_sig_pubkey)
        
        # Re-encrypt the data and then decrypt it
        # Getting data from ipfs
        for ipfsHash in data['ipfsHashes'].values():
            enc_data = self.api.cat(ipfsHash)
            data = msgpack.loads(enc_data)

            file_name = data[b'file_name']

            message_kit = UmbralMessageKit.from_bytes(data[b'file_data'])
            
            data_source = Enrico.from_public_keys(
                verifying_key=data[b'data_source'],
                policy_encrypting_key=policy_pubkey
            )

            plaintext = None
            try:
                start = timer()
                retrieved_plaintexts = bob.retrieve(
                    message_kit,
                    label=label,
                    enrico=data_source,
                    alice_verifying_key=alices_sig_pubkey
                )
                end = timer()
                plaintext = retrieved_plaintexts[0]

            except Exception as e:
                # We just want to know what went wrong and continue the demo
                traceback.print_exc()

            target = os.path.join(target_path, file_name.decode())
            print(f'Writing data to {target}')

            with open(target, 'wb') as f:
                f.write(plaintext)

if __name__ == '__main__':
  fire.Fire(nuCLI)