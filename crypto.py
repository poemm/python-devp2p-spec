
# Copyright 2018 Paul Dworzanski
# TODO: choose and open source license



"""
Below is all the crypto stuff used.

Must install:
sudo apt-get install python3-sha3 python3-cryptography
"""

import sha3
import hashlib
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.constant_time import bytes_eq
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# generate a random number
def generate_priv_key() -> int:
  return ec.generate_private_key(ec.secp256k1(), default_backend()).private_numbers().private_value

# given private key, derive the public key (i.e. node ID)
def get_nodeid(priv_key: int) -> str:
  priv_key_point = ec.derive_private_key(priv_key, ec.SECP256K1(), default_backend())
  pub_key_point = priv_key_point.public_key()
  #print(pub_key_point.public_numbers().x,pub_key_point.public_numbers().y)
  pub_key_hexstr = hex(pub_key_point.public_numbers().x)[2:] + hex(pub_key_point.public_numbers().y)[2:]
  return pub_key_hexstr

# this is just like function above, but the last step uses functions in the cryptography library
def get_nodeID_(priv_key: int) -> str:
  # this is same as above, but uses their tools
  priv_key_point = ec.derive_private_key(priv_key, ec.SECP256K1(), default_backend())
  pub_key_point = priv_key_point.public_key()
  pub_key_bytes = pub_key_point.public_bytes(encoding=serialization.Encoding.DER,format=serialization.PublicFormat.SubjectPublicKeyInfo)
  pub_key_hexstr = pub_key_bytes.hex()
  #pub_key_int = int.from_bytes(pub_key_bytes,byteorder='big')
  return pub_key_hexstr[-128:]

# agree on shared secret
def ecdh_agree(priv_key: int, pub_key) -> bytes:
  if type(pub_key) == int:
    pub_key_bytes = pub_key.to_bytes((pub_key.bit_length() + 7) // 8, 'big')
  elif type(pub_key) == str:
    if pub_key[:2] == '0x':
      pub_key = pub_key[2:]
    pub_key_bytes = bytes.fromhex(pub_key)
  else:
    return None
  pub_key_bytes = bytes([0x04]) + pub_key_bytes
  priv_key_point = ec.derive_private_key(priv_key, ec.SECP256K1(), default_backend())
  pub_key_point = ec.EllipticCurvePublicNumbers.from_encoded_point(ec.SECP256K1(), pub_key_bytes).public_key(default_backend())
  shared_secret = priv_key_point.exchange(ec.ECDH(), pub_key_point)
  return shared_secret

# sign a message with a private key
def sign(privkey,msg):
  priv_key_point = ec.derive_private_key(priv_key, ec.SECP256K1(), default_backend())
  dummy_256_bit_hash_func = hashes.SHA256()
  sig = priv_key_point.sign( msg, ec.ECDSA(utils.Prehashed(dummy_256_bit_hash_func)) )
  # TODO: this sig is wrong, need 65 byte output, not 72
  return sig

def keccak256(msg):
  k = sha3.keccak_512()
  k.update(b"data")
  return k.hexdigest()


# NIST SP 800-56 Concatenation Key Derivation Function (KDF)
# we only need key_length=32, so we simplify things, see geth's crypto/ecies/ecies.go for full implementation
def KDF32(key_material): 
  m = hashlib.sha256()
  m.update(bytes([0,0,0,1]))
  m.update(key_material)
  return m.digest()

#HMAC using the SHA-256 hash function.
def MAC(key, msg):
  h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
  h.update(msg)
  return h.finalize()

#the AES-128 encryption function in CTR mode.
def AES_encrypt(key, iv, msg): 
  cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
  encryptor = cipher.encryptor()
  ciphertext = encryptor.update(msg) + encryptor.finalize()
  return ciphertext

#the AES-128 decryption function in CTR mode.
def AES_encrypt(key, iv, ciphertext): 
  cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
  decryptor = cipher.decryptor()
  msg = decryptor.update(ciphertext) + decryptor.finalize()
  return msg









def test_crypto():
  """
   there is a blog post about private key 0x60cf347dbc59d31c1358c8e5cf5e45b822ab85b79cb32a9f3d98184779a9efc2
         https://medium.freecodecamp.org/how-to-create-a-bitcoin-wallet-address-from-a-private-key-eca3ddd9c05f
  """
  # both do key exchange, hope same secret
  priv_key1 = 0x60cf347dbc59d31c1358c8e5cf5e45b822ab85b79cb32a9f3d98184779a9efc2
  priv_key2 = 0xbe6be2acc154ab45f1989683d29d219cf69f9e7ddc891f412054c3cec80d0007
  nodeID1 = get_nodeID(priv_key1)
  nodeID2 = get_nodeID(priv_key2)
  sec1 = ecdh_agree(priv_key1, nodeID2)
  sec2 = ecdh_agree(priv_key2, nodeID1)
  if sec1 != sec2:
    return False

  if get_nodeID_(priv_key1) != get_nodeID(priv_key1):
    return False

  if get_nodeID_(priv_key2) != get_nodeID(priv_key2):
    return False

  return True









if __name__ == "__main__":
  test_crypto()


