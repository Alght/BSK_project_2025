from Crypto.Hash import SHA256
from Crypto.Cipher import AES
import os
import logging
from cryptography.hazmat.primitives.asymmetric import rsa
from pyhanko.sign import signers
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
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
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import fields, signers
from hashlib import sha256
import io
from cryptography.exceptions import UnsupportedAlgorithm

logging.basicConfig(level=logging.INFO)


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
    Derive a 256-bit SHA key.

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
    encrypted_private_key = cipher_aes.encrypt(private_key_padded)
    return iv + encrypted_private_key

def decrypt_private_key(encrypted_data, aes_key):
    """
    Decrypt private RSA key using AES key.

    Parameters:
        encrypted_data (bytes): byte string consisting of a 16-byte iv and AES-encrypted RSA key
        aes_key (bytes): The AES key (32 bytes) used for decryption.

    Returns:
        rsa.RSAPrivateKey: RSA private key object.

    """
    try:
        iv = encrypted_data[:16]
        encrypted_private_key = encrypted_data[16:]
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
        decrypted_padded = cipher_aes.decrypt(encrypted_private_key)
        padding_length = decrypted_padded[-1]
        if padding_length < 1 or padding_length > 16:
            return None
        private_key = decrypted_padded[:-padding_length]
        private_key = serialization.load_pem_private_key(
            private_key,
            password=None,
        )
        return private_key

    except (ValueError, UnsupportedAlgorithm, TypeError) as e:
        # Log or handle decryption error as needed
        logging.error(f"Failed to decrypt private key: {e}", exc_info=True)
        return None

def create_keys(pin, file_path):
    """
    Generate RSA key pair, derive AES key from PIN, encrypt the private key, and save both keys to files.

    Parameters:
        pin (str): User-provided PIN used to derive the AES key.
        file_path (str): Path where the encrypted private key will be saved (PEM format).

    Side Effects:
        - Saves the encrypted private key to `file_path`.
        - Saves the public key to `file_path` with `_pub.pem` suffix.
        - Logs debug messages about the operation.
        - Logs errors if key creation or file operations fail.

    Returns:
        None

    Raises:
        Logs exceptions internally but does not propagate them.
    """
    try:
        key = generate_rsa_key()
        aes_key = derive_aes_key(pin)
        encrypted_data = encrypt_private_key(key, aes_key)
        save_encrypted_private_key(encrypted_data, file_path)
        pub_key_path = os.path.splitext(file_path)[0] + "_pub.pem"
        save_public_key(key.public_key(), pub_key_path)
        logging.debug(f"Encrypted private key saved to {file_path}")
    except Exception as e:
        logging.error(f"Error creating keys: {e}", exc_info=True)


def save_public_key(public_key, output_file):
    """
    Save an RSA public key to a PEM-formatted file.

    Parameters:
        public_key (rsa.RSAPublicKey): The RSA public key to save.
        output_file (str): Path to the output file.

    Side Effects:
        - Writes the public key in PEM format to the file.
        - Logs the save operation.

    Returns:
        None   
    """
    key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.PKCS1
    )
    with open(output_file, "wb") as f:
        f.write(key)
    logging.debug(f"Public key saved to {output_file}")


def save_encrypted_private_key(encrypted_private_key, output_file):
    """
    Save an AES-encrypted RSA private key to a binary file.

    Parameters:
        encrypted_private_key (bytes): Encrypted private key data.
        output_file (str): Path to the output file.

    Side Effects:
        - Writes the encrypted key to the file.
        - Logs the save operation.

    Returns:
        None        
    """
    with open(output_file, "wb") as f:
        f.write(encrypted_private_key)
    logging.debug(f"Privat key saved to {output_file}")


def prepare_public_key(file_path):
    """
    Reads public key from .pem file and returns it in DER encoding

    Parameters:
        file_path (str): Path to the PEM-formatted public key file.

    Returns:
        bytes: RSA public key bytes with DER encoding format.
        
    Side Effects:
        - Logs debug messages about the operation.
    """
    logging.debug(f"prepare_public_key")
    with open(file_path, "rb") as f:
        public_key = serialization.load_pem_public_key(
            f.read(), backend=default_backend()
        )
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return public_key_bytes


def load_and_decrypt_private_key(file_path, pin):
    """
    Reads encrypted private key from .pem file and returns it in DER encoding

    Parameters:
        file_path (str): Path to the PEM-formatted public key file.

    Returns:
        rsa.RSAPrivateKey: RSA private key object.
        
    Side Effects:
        - Logs debug messages about the operation.
    """
    logging.debug("load_and_decrypt_private_key")

    with open(file_path, "rb") as f:
        encrypted_data = f.read()

    aes_key = derive_aes_key(pin)
    private_key = decrypt_private_key(encrypted_data, aes_key)

    logging.debug("Private key decrypted successfully")
    logging.debug(private_key)

    return private_key


def verify_pdf(pdf_file_path, public_key):
    """
    Verify the digital signature of a signed PDF against a provided public key.

    Parameters:
        pdf_file_path (str): Path to the signed PDF file.
        public_key (Crypto.PublicKey.RSA.RsaKey): RSA public key to compare with the signer's certificate.

    Returns:
        bool: True if the signature is cryptographically valid and matches the provided public key, False otherwise.

    Side Effects:
        - Logs debugging information about the verification process.
        - Reads and parses the PDF file.

    Notes:
        - The function compares SHA-256 hashes of the provided public key to hash from the certificate.
        - Requires the PDF to have exactly one embedded signature.
    """

    logging.debug("verify_pdf")
    try:
        with open(pdf_file_path, "rb") as f:
            reader = PdfFileReader(f)
            if len(reader.embedded_signatures) == 0:
                logging.debug("No signatures found.")
                return False
            
            # validate signature
            try:
                embedded_sig = reader.embedded_signatures[0]
                validation_result = validate_pdf_signature(embedded_sig)
                if not (validation_result.intact and validation_result.valid):
                    logging.debug("Signature failed cryptographic validation.")
                    return False
            except Exception as e:
                    logging.debug("Signature failed cryptographic validation.")
                    return False



            # get key from certificate
            signer_cert = embedded_sig.signer_cert
            document_key = signer_cert.public_key
            cert_der = document_key.dump()

            # validate signature
            provided_pubkey_der = public_key.export_key(format="DER")  # PyCryptodome key

            # Hash
            cert_pubkey_hash = sha256(cert_der).digest()
            public_key_hash = sha256(provided_pubkey_der).digest()

            res = cert_pubkey_hash  == public_key_hash

            if res:
                logging.debug("Signature is valid and public key matches.")
                return True
            else:
                logging.debug(f"Signature valid, but public key does not match. Reason: {validation_result.summary()}")
                return False
    except Exception as e:
        logging.error(f"Verification failed: {e}", exc_info=True)
        return False

def create_cert(private_key, save=False):
    """
    Generate a self-signed X.509 certificate using the provided RSA private key.

    Parameters:
        private_key (rsa.RSAPrivateKey): The private key to sign the certificate.
        save (bool): If True, saves the certificate to a file named 'rsa_cert.pem'.

    Returns:
        x509.Certificate: A self-signed X.509 certificate.

    Side Effects:
        - Optionally writes the certificate to 'rsa_cert.pem'.
        - Logs debug messages including key types and certificate creation steps.
    """
    logging.debug("create_cert")
    subject = issuer = x509.Name(
        [    
            x509.NameAttribute(NameOID.COUNTRY_NAME, "PL"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Pomorskie"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Gdansk"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Gdansk University of Technology"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "WETI"),
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
                decipher_only=False,
            ),
            critical=True,
        ).sign(private_key, hashes.SHA256())
    )
    if save:
        with open("rsa_cert.pem", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
    return cert


def sign_pdf(pdf_file_path, cert, key, change_name=False):
    """
    Digitally sign a PDF using an X.509 certificate and RSA private key.

    Parameters:
        pdf_file_path (str): Path to the PDF file to be signed.
        cert (x509.Certificate): The X.509 certificate used for signing.
        key (rsa.RSAPrivateKey): The RSA private key corresponding to the certificate.
        change_name (bool): If True, output file will be named with '_signed.pdf' suffix.

    Side Effects:
        - Writes a new signed PDF file to disk (overwrites input if `change_name` is False).
        - Logs and suppresses exceptions during signing.

    Returns:
        bool: information if PDF was signed
    """
    logging.debug("sign_pdf")
    if not isinstance(cert, x509.Certificate):
        logging.error(f"Invalid certificate type: {type(cert)}. Must be x509.Certificate.")
        return False
    if not isinstance(key, rsa.RSAPrivateKey):
        logging.error(f"Invalid key type: {type(key)}. Must be RSAPrivateKey.")
        return False
    try:
        cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
        _, _, der_bytes = pem.unarmor(cert_pem)
        asn1_crt = asn1x509.Certificate.load(der_bytes)
    except Exception as e:
        logging.error(f"Failed to convert certificate: {e}", exc_info=True)
        return False
    try:
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        asn1_key = load_private_key_from_pemder_data(key_pem, None)
    except Exception as e:
        logging.error(f"Failed to convert private key: {e}", exc_info=True)
        return False
    try:    
        signer = signers.SimpleSigner(
            signing_cert=asn1_crt,
            signing_key=asn1_key,
            cert_registry=SimpleCertificateStore(),
        )

        base, ext = os.path.splitext(pdf_file_path)
        signed_pdf_path = f"{base}_signed{ext}" if change_name else pdf_file_path

        with open(pdf_file_path, "rb") as f:
            pdf_bytes = f.read() 

        pdf_stream = io.BytesIO(pdf_bytes)
        w = IncrementalPdfFileWriter(pdf_stream)
        fields.append_signature_field(
            w, sig_field_spec=fields.SigFieldSpec("Signature", box=(200, 600, 400, 660))
        )
        meta = signers.PdfSignatureMetadata(field_name="Signature")
        pdf_signer = signers.PdfSigner(meta, signer=signer, stamp_style=stamp.TextStampStyle(stamp_text="PDF was signed by user A\nSigned by: %(signer)s\nTime: %(ts)s",),)

        with open(signed_pdf_path, "wb") as out_f:
            pdf_signer.sign_pdf(w, output=out_f)
        logging.debug(f"Signed PDF written to {signed_pdf_path}")
    except Exception as e:
        logging.error(f"Failed to sign PDF: {e}", exc_info=True)
        return False
    return True


def verify_is_pdf_signed(pdf_file_path):
    """
    Check if chosen PDF is signed.

    Parameters:
        pdf_file_path (str): Path to the signed PDF file.

    Returns:
        bool: True if the PDF contains any signature.
    """
    try:
    
        with open(pdf_file_path, "rb") as f:
            reader = PdfFileReader(f)
            logging.error(reader.embedded_signatures)
            return len(reader.embedded_signatures) > 0
    except Exception as e:
        logging.error(f"Failed to verify PDF signature: {e}", exc_info=True)
        return False

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
    if not isinstance(pdf_file_path, str):
        logging.error("pdf_file_path must be a string.")
        return False
    if verify_is_pdf_signed(pdf_file_path):
        logging.error("PDF is signed")
        return False
    cert = create_cert(key)
    is_signed = sign_pdf(pdf_file_path, cert, key)
    return is_signed
