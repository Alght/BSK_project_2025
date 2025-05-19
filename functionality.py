from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
import os
import logging
from cryptography.hazmat.primitives.asymmetric import rsa
from pyhanko.sign import signers
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign.fields import SigFieldSpec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
from pyhanko_certvalidator.registry import SimpleCertificateStore
from asn1crypto import pem
from asn1crypto import x509 as asn1x509
from pyhanko.keys import load_private_key_from_pemder_data
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko.sign import fields, signers
from pyhanko import stamp
from pyhanko.pdf_utils import text, images
from pyhanko.pdf_utils.font import opentype
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import fields, signers
from hashlib import sha256
logging.basicConfig(level=logging.DEBUG)


def generate_rsa_key():
    """
    Generate a 4096-bit RSA private key.

    Uses a public exponent of 65537 and the default cryptographic backend.

    Returns:
        rsa.RSAPrivateKey: A newly generated RSA private key object.
    """
    return rsa.generate_private_key(
        public_exponent=65537, key_size=4096, backend=default_backend()
    )

def derive_aes_key(pin):
    """
    Derive a a 256-bit SHA key.

    Parameters:
        pin (str): User-provided pin.

    Returns:
        bytes: A 32-byte AES key derived from the SHA-256 hash of the pin.
    """
    hasher = SHA256.new(pin.encode())
    return hasher.digest()

def encrypt_private_key(private_key, aes_key):
    """
    Encrypt private RSA key using AES key.

    Parameters:
        private_key (rsa.RSAPrivateKey): The RSA private key object to encrypt.
        aes_key (bytes): AES bytes.

    Returns:
        bytes: A byte string with initialization vector and encrypted RSA private key
    """
    key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    iv = os.urandom(16)
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    padding_length = 16 - (len(key) % 16)
    private_key_padded = key + bytes([padding_length]) * padding_length
    encrypted_privat_key = cipher_aes.encrypt(private_key_padded)
    return iv + encrypted_privat_key

def decrypt_private_key(encrypted_data, aes_key):
    """decrypt private key using AES key, takes iv and encrypted key as arguments"""
    iv = encrypted_data[:16]
    encrypted_private_key = encrypted_data[16:]
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_padded = cipher_aes.decrypt(encrypted_private_key)
    padding_length = decrypted_padded[-1]
    if padding_length < 1 or padding_length > 16:
        raise ValueError("Invalid padding")
    private_key = decrypted_padded[:-padding_length]
    private_key = serialization.load_pem_private_key(
        private_key,
        password=None,
    )
    return private_key

def create_keys(pin, file_path):
    """generate RSA keys, AES key and save keys to files specified py path"""
    key = generate_rsa_key()
    aes_key = derive_aes_key(pin)

    encrypted_data = encrypt_private_key(key, aes_key)
    save_encrypted_privat_key(encrypted_data, file_path)

    logging.debug(f"Encrypted private key saved to {file_path}")
    logging.debug(f"Private key: {key}")
    logging.debug(f"Public key: {key.public_key()}")
    pub_key_path = file_path.replace(".pem", "_pub.pem")
    save_public_key(key.public_key(), pub_key_path)

def save_public_key(public_key, output_file):
    key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.PKCS1
    )
    with open(output_file, "wb") as f:
        f.write(key)
    logging.debug(f"Public key saved to {output_file}")

def save_encrypted_privat_key(encrypted_privat_key, output_file):
    with open(output_file, "wb") as f:
        f.write(encrypted_privat_key)
    logging.debug(f"Privat key saved to {output_file}")


def prepare_public_key(file_path):
    """load public key"""
    logging.debug(f"prepare_public_key")
    with open(file_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
        logging.debug(f"Public key: {public_key}")
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        logging.debug(f"Public key: {public_key}")
        return public_key_bytes



def load_and_decrypt_private_key(file_path, pin):
    logging.debug("load_and_decrypt_private_key")

    with open(file_path, "rb") as f:
        encrypted_data = f.read()

    aes_key = derive_aes_key(pin)
    private_key = decrypt_private_key(encrypted_data, aes_key)

    logging.debug("Private key decrypted successfully!")
    logging.debug(private_key)

    return private_key


def verify_pdf(pdf_file_path, public_key):
    logging.debug("verify_pdf")
    with open(pdf_file_path, "rb") as f:
        reader = PdfFileReader(f)
        embedded_sig = reader.embedded_signatures[0]
        validation_result = validate_pdf_signature(embedded_sig)

        hash_algorithm = hashes.Hash(hashes.SHA256(), backend=default_backend())
        # hash_algorithm.update(public_key)
        hash_algorithm.update(public_key.export_key(format='DER'))

        public_key_hash = hash_algorithm.finalize()

        # Extract the public key from the signer certificate and hash it
        signer_cert = embedded_sig.signer_cert
        document_key = signer_cert.public_key  # Get the public key object

        # Convert public key to bytes
        cert_der = document_key.dump()

        # Generate SHA-256 hash of the public key
        document_key_hash = sha256(cert_der).hexdigest()

        # Hash the document's public key
        document_hash_algorithm = hashes.Hash(hashes.SHA256(), backend=default_backend())
        document_hash_algorithm.update(cert_der)
        document_key_hash = document_hash_algorithm.finalize()


        

        res = document_key_hash == public_key_hash  # If hashes match, signature is valid

        if validation_result.intact and validation_result.valid and res:
            logging.debug("Signature is valid.")
            return True
        else:
            logging.debug(f"Signature is invalid. Reason: {validation_result.summary()}")
            return False


def create_cert(private_key, save=False):
    logging.debug("create_cert")
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PG"),
            x509.NameAttribute(NameOID.COMMON_NAME, "pg.edu.pl"),
        ]
    )

    public_key = private_key.public_key()

    logging.debug(type(public_key))
    logging.debug(type(private_key))

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now())
        .not_valid_after(datetime.now() + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True) 
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True, 
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        .sign(private_key, hashes.SHA256())
    )
    if save:
        with open("rsa_cert.pem", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
    return cert


def sign_pdf(pdf_file_path, cert, key):
    logging.debug("sign_pdf")
    logging.debug(f"Certificate Type: {type(cert)}")
    logging.debug(f"Key Type: {type(key)}")

    """turn cert from cryptography.x509 to asn1crypto.x509"""
    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
    _, _, der_bytes = pem.unarmor(cert_pem)
    asn1_crt = asn1x509.Certificate.load(der_bytes)

    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    asn1_key = load_private_key_from_pemder_data(key_pem, None)

    signer = signers.SimpleSigner(
        signing_cert=asn1_crt,
        signing_key=asn1_key,
        cert_registry=SimpleCertificateStore(),
    )

    signed_pdf_path = pdf_file_path.replace(".pdf", "_signed.pdf")

    with open(pdf_file_path, "rb") as f:
        w = IncrementalPdfFileWriter(f)
        fields.append_signature_field(
        w, sig_field_spec=fields.SigFieldSpec(
            'Signature', box=(200, 600, 400, 660)
        )
        )
        meta = signers.PdfSignatureMetadata(field_name='Signature')
        pdf_signer = signers.PdfSigner(
            meta,
            signer=signer,
            stamp_style=stamp.TextStampStyle(
                # The 'signer' and 'ts' will be interpolated
                stamp_text='This is custom text!\nSigned by: %(signer)s\nTime: %(ts)s',
            ),
        )

        with open(signed_pdf_path, "wb") as out_f:

            pdf_signer.sign_pdf(w, output=out_f)

        logging.debug(f"Signed PDF written to {signed_pdf_path}")

def sign_pdf_full(pdf_file_path, key):
    """
    Create a certificate and use it to sign a PDF.

    This function generates a self-signed certificate from the given RSA private key
    and uses it to apply a digital signature to the specified PDF file.

    Parameters:
        pdf_file_path (str): Path to the PDF file to be signed.
        key (rsa.RSAPrivateKey): The RSA private key used for signing.

    Side Effects:
        - Modifies the PDF file at `pdf_file_path` by adding a digital signature.
    """
    cert = create_cert(key)
    sign_pdf(pdf_file_path,cert, key)
        