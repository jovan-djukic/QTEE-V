#!/usr/bin/env python3

import binascii
import hashlib
import hmac
import json
import socket
import ssl
import sys
import os 
import ipaddress
from typing import Tuple, Union
import cryptography
import requests
import pprint
import tempfile
import base64
import re

from urllib.parse import urljoin
from urllib.parse import quote 

from pathlib import Path

from datetime import datetime

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PrivateFormat
from cryptography.hazmat.primitives.serialization import NoEncryption
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

from threading import Thread
from threading import Semaphore


HOST = "127.0.0.1"

CONTROLLER_HOST                = "127.0.0.1"
CONTROLLER_PORT                = "8000"
CONTROLLER_GET_NONCE_PATH      = "get_nonce"
CONTROLLER_REGISTER_PATH       = "register"
CONTROLLER_CONFIGURATION_PATH  = "configuration"

KME_PORT = "443"

QKD_CA_CERTIFICATE = "-----BEGIN CERTIFICATE-----\nMIIDbTCCAlWgAwIBAgIQCzuhkEQXTouuETnIFrtF1jANBgkqhkiG9w0BAQsFADBn\nMSwwKgYDVQQDDCNhY2N0LTI1NjMuZXRzaS1xa2QtYXBpLnF1a2F5ZGVlLmNvbTEe\nMBwGA1UECgwVUXVLYXlEZWUgYWNjb3VudCAyNTYzMRcwFQYDVQQLDA5TZXJ2ZXIg\ncm9vdCBDQTAgFw0yNTA1MjYwODMxMzlaGA8yMTI1MDUwMzA4MzEzOVowZzEsMCoG\nA1UEAwwjYWNjdC0yNTYzLmV0c2ktcWtkLWFwaS5xdWtheWRlZS5jb20xHjAcBgNV\nBAoMFVF1S2F5RGVlIGFjY291bnQgMjU2MzEXMBUGA1UECwwOU2VydmVyIHJvb3Qg\nQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC6fv8Hp8hL7P6Rs3Zc\nX3oHL6hEXbx5hmSPLFvSIpLnF1iZepdlJtXJiq2oVZNcdtDgnYA5ugl6CGQE8v3A\n79hxrWOSSfysYryoIBBYSvaEPEN16TSKcY7+cAnSU8fu736uRhKwz2jeJw2g+4pb\nlcmsJhLq40F23Px+XkpA99DPIGHWWy2ZelcddnP1M99/l937V2AvGaM+P71NMS9a\nF/K/2iiDOiAQ3XZXVIjmsdSMHth2780U80wiAaH2PsOILMbKNLdxDLYIJa5awmXY\n1D8Dik9Ot7e0It+ZfdaXxUHBxnTj7CgajqhOvd78p2PCwMhZ61DO+5subpzhywxE\nt92/AgMBAAGjEzARMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB\nAAuWsi3TFKGn1H6raS0aSw6JqE5c/PUMGRTBDzmSpIUMjnaG/9Ise1SGxujAYvpm\nahExKKFkgTuSV4GmYL1n4Yakls3sr9hbP40L2wJLus+psfGKsN+Xa3hwyFrQVyKY\ndNpIH+AIhH/nI2WKyYnhv0dE2PR/UzR3AtCum/uu8C2JnY0qnBlQ3ooOopti0+MK\nzEHJBAK2jxm9vjEgHs+zHKIxOiuCM6jmPZsG4PdBWkcf1C6Coof0kfO3vednsE/B\n0Q1c9TemcUbH6OR0kDxJFV/Alsim2wolJ722QOlBB2+m88POeSqN9JLxcj3pQe53\nwkKhllHrkuVRW7pw4wXXn8w=\n-----END CERTIFICATE-----"
REPETITOR_CA_CERTIFICATE = "-----BEGIN CERTIFICATE-----\nMIIDrzCCApegAwIBAgIUXeRoaA0s2FWtqv9KV6xjUPLMHgkwDQYJKoZIhvcNAQEL\nBQAwXjELMAkGA1UEBhMCUlMxCzAJBgNVBAgTAlJTMREwDwYDVQQHEwhCZWxncmFk\nZTEMMAoGA1UEChMDRVRGMQwwCgYDVQQLEwNSVEkxEzARBgNVBAMTCk15IFJvb3Qg\nQ0EwHhcNMjUwOTA2MTAyNzAwWhcNMzAwOTA1MTAyNzAwWjBeMQswCQYDVQQGEwJS\nUzELMAkGA1UECBMCUlMxETAPBgNVBAcTCEJlbGdyYWRlMQwwCgYDVQQKEwNFVEYx\nDDAKBgNVBAsTA1JUSTETMBEGA1UEAxMKTXkgUm9vdCBDQTCCASIwDQYJKoZIhvcN\nAQEBBQADggEPADCCAQoCggEBANtfOpPGqxY8mkRxlNMRQn6wVQ0aUeO9zjLANhZ9\nbG81fV1uP9i5pJ/wgUEx2B3b1kj0nD/a51xp++Y+/12y52ZbGPpYBOJu5cb5aFTw\nJ95OB+ri8c1uqFwRA2mxrSRUgrlRuZKsbPLnZeNC/2t5anR37GncsZWgWppgJ8nO\nUXXymXy2QK1k2hMAhO4uIGVmzG8eHvpCMEMMj+9hlhE2y8jId0GyHA2EWyuQNOe3\nT7go91MotJY+/uPsEY8uSajRrN/fUcXqQrBysZDMbPiHlvaG/NyVGI+vQBPEULNE\nebG/47G79h542xwpflz6H9VOpboXjBgzgyvzLuGlJzSL+20CAwEAAaNlMGMwDgYD\nVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFIS8fn+Ob/PH\npPC5AIgKR7GWKOJFMCEGA1UdEQQaMBiHBH8AAAGHEAAAAAAAAAAAAAAAAAAAAAEw\nDQYJKoZIhvcNAQELBQADggEBAHmXsmyq+KJTm2/+lXoZnpB/fM16T9dqypQdzIme\nK0PcrNzcJzxF4dxi7IJWr97ICRJfSqKppUVLBWGVYXau6Prtbf+dXs9KM0Juzo9a\nGYD3tNfdlAmI4ZSMt4H/EwaCO5MiXMSwvtg6qMpWjDXjJOvTIyDdWIe0JE+Soz2T\ncGr1d8RyvYUAL0whxbAqAVAKBe9c4MTm1rlS5hMrpTVTSmI+HKPJyzZvvoiemzZg\nAw8+YxNOFwljTCl4ZCi5/PME9utT3IWqQUhrGwa4LMduRaieSnjIstNurvNsOBnd\ntGAHFnSILfyZq0Z4vpnMhr4D6UmLvsis0W/lBAMkVlSJvKQ=\n-----END CERTIFICATE-----"
# TODO: remove after testing
with open ( "./cfssl/client-root-ca.crt", "r" ) as file:
    REPETITOR_CA_CERTIFICATE = file.read ( )

def get_configuration ( 
        controller_host: str,
        controller_port: str,
        controller_get_nonce_path: str,
        controller_register_path: str,   
        controller_configuration_path: str,
        repetitor_id: str,
        repetitor_url: str 
) -> dict:
    get_nonce_response = requests.get(
        f"http://{controller_host}:{controller_port}/{controller_get_nonce_path}",
        params = { "repetitor_id": repetitor_id },
        timeout = 10
    )    

    # print ( get_nonce_response.json ( ) )

    register_response = requests.post (
        f"http://{controller_host}:{controller_port}/{controller_register_path}",
        json = {
            "attestation_report": "dummy_attestation_report",
            "repetitor_id": repetitor_id,
            "repetitor_url": repetitor_url
        },
        timeout = 10
    ) 

    configuration_response = requests.post (
        f"http://{controller_host}:{controller_port}/{controller_configuration_path}",
        json = {
            "attestation_report": "dummy_attestation_report",
            "repetitor_id": repetitor_id,
            "repetitor_url": repetitor_url
        },
        timeout = 10
    ) 

    configuration = configuration_response.json ( )

    return configuration

def build_key ( ) -> rsa.RSAPrivateKey:
    key = rsa.generate_private_key ( public_exponent=65537, key_size=2048 )

    return key

def build_csr ( key: rsa.RSAPrivateKey, common_name: str ) -> bytes:
    csr = (
        x509.CertificateSigningRequestBuilder ( )
        .subject_name (
            x509.Name (
                [x509.NameAttribute ( NameOID.COMMON_NAME, f"{common_name}" ) ]
            )
        )
        .add_extension (
            x509.SubjectAlternativeName (
                [
                    x509.DNSName ( f"{common_name}" ),
                    # x509.DNSName ( "localhost" ),
                    # x509.IPAddress ( ipaddress.IPv4Address ( "127.0.0.1" ) ),  # ← fixed
                    # x509.IPAddress ( ipaddress.IPv6Address ( "::1" ) )
                ]
            ),
            critical = False,
        )
        .sign( key, hashes.SHA256 ( ) )
    )
    csr_pem = csr.public_bytes ( serialization.Encoding.PEM )

    return csr_pem

def kme_get_status ( 
        private_key, 
        certificate, 
        ca_root_certificate, 
        kme_host, 
        kme_port, 
        kme_slave
):

    url = f"https://{kme_host}:{kme_port}/api/v1/keys/{kme_slave}/status"

    # Convert key object -> PEM bytes
    key_pem = private_key.private_bytes (
        encoding = Encoding.PEM,
        format = PrivateFormat.TraditionalOpenSSL,  # or PrivateFormat.PKCS8 if your server expects that
        encryption_algorithm = NoEncryption ( )
    )

    response = None
    # Write cert, key, and CA to temp files for requests
    with tempfile.NamedTemporaryFile ( ) as certificate_file, \
         tempfile.NamedTemporaryFile ( ) as key_file,  \
         tempfile.NamedTemporaryFile ( ) as ca_certificate_file:

        certificate_file.write ( certificate.encode ( "utf-8" ) )
        key_file.write ( key_pem )
        ca_certificate_file.write ( ca_root_certificate.encode ( "utf-8" ) )

        certificate_file.flush ( )
        key_file.flush ( )
        ca_certificate_file.flush ( )

        certificate_file_path    = certificate_file.name
        key_file_path            = key_file.name
        ca_certificate_file_path = ca_certificate_file.name

        response = requests.get (
            url = url,
            cert = ( certificate_file_path, key_file_path ),   # paths to client cert & key
            verify = ca_certificate_file_path             # path to CA bundle
        )

    return response

def kme_get_key ( 
        private_key, 
        certificate, 
        ca_root_certificate, 
        kme_host, 
        kme_port, 
        kme_slave
):
    url = f"https://{kme_host}:{kme_port}/api/v1/keys/{kme_slave}/enc_keys"

    # Convert key object -> PEM bytes
    key_pem = private_key.private_bytes (
        encoding = Encoding.PEM,
        format = PrivateFormat.TraditionalOpenSSL,  # or PrivateFormat.PKCS8 if your server expects that
        encryption_algorithm = NoEncryption ( )
    )

    response = None
    # Write cert, key, and CA to temp files for requests
    with tempfile.NamedTemporaryFile ( ) as certificate_file, \
         tempfile.NamedTemporaryFile ( ) as key_file,  \
         tempfile.NamedTemporaryFile ( ) as ca_certificate_file:

        certificate_file.write ( certificate.encode ( "utf-8" ) )
        key_file.write ( key_pem )
        ca_certificate_file.write ( ca_root_certificate.encode ( "utf-8" ) )

        certificate_file.flush ( )
        key_file.flush ( )
        ca_certificate_file.flush ( )

        certificate_file_path    = certificate_file.name
        key_file_path            = key_file.name
        ca_certificate_file_path = ca_certificate_file.name

        response = requests.get (
            url = url,
            cert = ( certificate_file_path, key_file_path ),   # paths to client cert & key
            verify = ca_certificate_file_path             # path to CA bundle
        )

    return response.json ( )

def kme_get_key_with_id ( 
        private_key, 
        certificate, 
        ca_root_certificate, 
        kme_host, 
        kme_port, 
        kme_master,
        key_id
):
    url = f"https://{kme_host}:{kme_port}/api/v1/keys/{kme_master}/dec_keys?key_ID={key_id}"

    # Convert key object -> PEM bytes
    key_pem = private_key.private_bytes (
        encoding = Encoding.PEM,
        format = PrivateFormat.TraditionalOpenSSL,  # or PrivateFormat.PKCS8 if your server expects that
        encryption_algorithm = NoEncryption ( )
    )

    response = None
    # Write cert, key, and CA to temp files for requests
    with tempfile.NamedTemporaryFile ( ) as certificate_file, \
         tempfile.NamedTemporaryFile ( ) as key_file,  \
         tempfile.NamedTemporaryFile ( ) as ca_certificate_file:

        certificate_file.write ( certificate.encode ( "utf-8" ) )
        key_file.write ( key_pem )
        ca_certificate_file.write ( ca_root_certificate.encode ( "utf-8" ) )

        certificate_file.flush ( )
        key_file.flush ( )
        ca_certificate_file.flush ( )

        certificate_file_path    = certificate_file.name
        key_file_path            = key_file.name
        ca_certificate_file_path = ca_certificate_file.name

        response = requests.get (
            url = url,
            cert = ( certificate_file_path, key_file_path ),
            verify = ca_certificate_file_path
        )

    return response.json ( )


def sign_with_cfssl ( ca_url: str, csr_pem: bytes ) -> str:
    """Return PEM cert (chain) or raise."""

    CA_PROFILE = "server"
    HEADERS    = {
        # "Authorization": "Bearer <token>",
        "Content-Type": "application/json"
    }

    payload = {
        "certificate_request": csr_pem.decode ( ),
        "profile": CA_PROFILE,
    }

    response = requests.post ( 
        ca_url, 
        headers = HEADERS, 
        json = payload,
    )

    response.raise_for_status ( )
    object = response.json ( )
    if ( object.get ( "success" ) is not True ):
        raise RuntimeError ( f"CFSSL error: {object.get ( 'errors' )}" )

    certificate_pem = object["result"]["certificate"]

    return certificate_pem

def generate_certificate ( ca_url: str, common_name: str ) -> None:
    key = build_key ( )

    csr_pem = build_csr ( key, common_name )

    certificate_pem = sign_with_cfssl ( ca_url, csr_pem )

    return key, certificate_pem

def send_message (
    private_key,
    certificate_pem: str,
    ca_certificate_pem: str,
    host: str,
    port: int,
    data: dict
):
    private_key_pem = private_key.private_bytes (
        encoding = Encoding.PEM,
        format = PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm = NoEncryption ( ),
    )

    # Prepare SSL context
    with tempfile.NamedTemporaryFile ( ) as certificate_file, \
         tempfile.NamedTemporaryFile ( ) as private_key_file:
        
        certificate_file.write ( certificate_pem.encode ( "utf-8" ) )
        private_key_file.write ( private_key_pem )
        certificate_file.flush ( )
        private_key_file.flush ( )

        context = ssl.SSLContext ( ssl.PROTOCOL_TLS_CLIENT )
        context.load_cert_chain (
            certfile = certificate_file.name,
            keyfile = private_key_file.name
        )
        context.load_verify_locations ( cadata = ca_certificate_pem )
        context.check_hostname = False
        # context.verify_mode = ssl.CERT_REQUIRED
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection ( ( host, port ) ) as my_socket:
            with context.wrap_socket ( my_socket ) as tls:
                print(f"[{datetime.now():%H:%M:%S}] Connected to {host}:{port} via mTLS")

                wire_bytes = ( json.dumps ( {
                    **data,
                    "message": data["message"]
                } ) + "\n" ).encode ( "utf-8" )
                message = wire_bytes + b"\n"

                tls.sendall ( message )

                # Optional: wait for server ack (or close immediately)
                response = tls.recv(4096)
                print("Server replied:", response.decode())

                tls.unwrap ( )

def receive_message (
    private_key,
    certificate_pem: str,
    ca_certificate_pem: str,
    host: str,
    port: int,
    client_whitelist: list[str],
    repetitor_id: str
):
    # Prepare server key/cert files for SSLContext
    private_key_pem = private_key.private_bytes (
        encoding = Encoding.PEM,
        format = PrivateFormat.TraditionalOpenSSL,  # or PKCS8
        encryption_algorithm = NoEncryption ( ),
    )

    # Write cert, key, and CA to temp files for requests
    with tempfile.NamedTemporaryFile ( ) as certificate_file, \
         tempfile.NamedTemporaryFile ( ) as private_key_file:
            
        certificate_file.write ( certificate_pem.encode ( "utf-8" ) )
        private_key_file.write ( private_key_pem )
        
        certificate_file.flush ( )
        private_key_file.flush ( )

        certificate_file_path = certificate_file.name
        private_key_file_path = private_key_file.name

        context = ssl.SSLContext ( ssl.PROTOCOL_TLS_SERVER )
        context.load_cert_chain ( 
            certfile = certificate_file_path, 
            keyfile = private_key_file_path
        )

        context.load_verify_locations ( cadata = ca_certificate_pem )

        context.verify_mode = ssl.CERT_REQUIRED  # require client cert

        with socket.socket ( socket.AF_INET, socket.SOCK_STREAM, 0 ) as my_socket:
            my_socket.setsockopt ( socket.SOL_SOCKET, socket.SO_REUSEADDR, 1 )
            my_socket.bind ( ( host, port ) )
            my_socket.listen ( 5 )

            print ( f"[{datetime.now():%H:%M:%S}][{repetitor_id}] mTLS listener on {host}:{port} (waiting…)" )

            connection, address = my_socket.accept ( )  # blocks here

            with context.wrap_socket ( connection, server_side = True ) as tls:
                # Handshake succeeded and client cert is chained to ca_pem
                peer_certificate_der = tls.getpeercert ( binary_form = True )

                peer_certificate = x509.load_der_x509_certificate ( peer_certificate_der )

                common_name = re.search (  r"CN=([^)>]+)", str ( peer_certificate.subject ) ).group ( 1 )

                if ( common_name not in client_whitelist and len ( client_whitelist ) > 0 ):
                    raise RuntimeError ( f"Client {common_name} not in whitelist" )

                # Read message
                chunks = []
                read = 0
                while True:
                    data = tls.recv ( 4096 )

                    if ( not data ):
                        break

                    chunks.append ( data )
                    read += len ( data )
                    
                    if ( b"\n" in data ):
                        break

                message = b"".join ( chunks )

                tls.sendall ( b"RECEIVED\n" )

                tls.unwrap ( )

                return common_name, message

# ---------- helpers: hex / base64 --------------------------------------------

def is_hex ( string: str ) -> bool:
    try:
        int ( string, 16 )
        return True
    except ValueError:
        return False

def b64_decode_tolerant ( string: str ) -> bytes:
    string = string.strip ( )

    missing = 0 if ( len ( string ) % 4 == 0 ) else 4 - ( len ( string ) % 4 )

    if ( missing != 0 ):
        string = string + ( "=" * missing )

    return base64.b64decode ( string, validate = False )

def b64_encode ( byte_array: bytes ) -> str:
    return base64.b64encode ( byte_array ).decode ( "ascii" )

def bytes_to_hex ( byte_array: bytes ) -> str:
    return binascii.hexlify ( byte_array ).decode ( "ascii" )

def hex_to_bytes ( string: str ) -> bytes:
    return binascii.unhexlify ( string.encode ( "ascii" ) )

def decode_master_key ( text: str ) -> bytes:
    """
    Your C decode_key(): if all hex (and even length) -> hex; else -> base64.
    """
    striped_text = text.strip()
    if ( len ( striped_text ) % 2 == 0 and all ( c in "0123456789abcdefABCDEF" for c in striped_text ) ):
        return hex_to_bytes ( striped_text )
    else:
        return b64_decode_tolerant ( striped_text )


# ---------- key derivation ----------------------------------------------------

def derive_keys ( master_key: bytes ) -> Tuple[bytes, bytes]:
    """
    aes_key = SHA256(master_key)
    hmac_key = SHA256(master_key || "Mac")
    """
    aes_key = hashlib.sha256 ( master_key ).digest ( )

    hmac_ctx = hashlib.sha256 ( )
    hmac_ctx.update ( master_key )
    hmac_ctx.update ( b"Mac" )

    hmac_key = hmac_ctx.digest ( )

    return aes_key, hmac_key


# ---------- AES-256-CBC (PKCS#7) ---------------------------------------------

def aes256_cbc_encrypt ( plaintext: bytes, key: bytes, iv: bytes ) -> bytes:
    padder    = padding.PKCS7 ( algorithms.AES.block_size ).padder ( )
    padded    = padder.update ( plaintext ) + padder.finalize ( )
    cipher    = Cipher ( algorithms.AES ( key ), modes.CBC ( iv ), backend = default_backend ( ) )
    encryptor = cipher.encryptor ( )

    return encryptor.update ( padded ) + encryptor.finalize ( )

def aes256_cbc_decrypt ( ciphertext: bytes, key: bytes, iv: bytes ) -> bytes:
    cipher    = Cipher ( algorithms.AES ( key ), modes.CBC ( iv ), backend = default_backend ( ) )
    decryptor = cipher.decryptor ( )
    padded    = decryptor.update ( ciphertext ) + decryptor.finalize ( )
    unpadder  = padding.PKCS7 ( algorithms.AES.block_size ).unpadder ( )

    return unpadder.update ( padded ) + unpadder.finalize ( )


# ---------- public API --------------------------------------------------------

def encrypt ( plaintext: Union[str, bytes], key_text: str ) -> str:
    """
    Returns Base64 blob of: IV_hex || ciphertext_base64 || tag_hex, all Base64-encoded.
    Accepts `key_text` as hex or base64 (compatible with your C).
    """
    if isinstance ( plaintext, str ):
        plaintext = plaintext.encode ( "utf-8" )

    master_key = decode_master_key ( key_text )
    aes_key, hmac_key = derive_keys ( master_key )

    # 16-byte random IV
    iv     = os.urandom ( 16 )
    iv_hex = bytes_to_hex ( iv )  # 32 chars

    # AES-256-CBC + PKCS#7
    ciphertext_binary = aes256_cbc_encrypt ( plaintext, aes_key, iv )
    ciphertext_b64    = b64_encode ( ciphertext_binary )

    # HMAC-SHA256 over ciphertext_base64 (ASCII)
    tag = hmac.new ( hmac_key, ciphertext_b64.encode ( "ascii" ), hashlib.sha256 ).digest ( )
    tag_hex = bytes_to_hex ( tag )  # 64 chars

    # assemble raw blob (ASCII): IVhex || cipherB64 || taghex
    blob_raw = ( iv_hex + ciphertext_b64 + tag_hex ).encode ( "ascii" )

    return b64_encode ( blob_raw )


def decrypt ( blob_base64: str, key_text: str ) -> bytes:
    """
    Accepts the Base64 blob produced above (or by your C encrypt()) and the master key
    (hex or base64, like your C). Returns plaintext **bytes**.
    """
    master_key = decode_master_key ( key_text )
    aes_key, hmac_key = derive_keys ( master_key )

    # decode whole blob
    blob = b64_decode_tolerant ( blob_base64 ).decode ( "ascii", errors="strict" )

    if ( len ( blob ) < 32 + 64 ):
        raise ValueError ( "Blob too short" )

    iv_hex         = blob[:32]
    tag_hex        = blob[-64:]
    ciphertext_b64 = blob[32:-64]

    print("tag_hex:", tag_hex)
    print("has uppercase:", any(c in "ABCDEF" for c in tag_hex))
    print("ciphertext_b64_len=", len(ciphertext_b64))
    print("ciphertext_b64=", repr(ciphertext_b64))

    # verify HMAC over ciphertext_base64
    calculated_tag     = hmac.new ( hmac_key, ciphertext_b64.encode ( "ascii" ), hashlib.sha256 ).digest ( )
    calculated_tag_hex = bytes_to_hex ( calculated_tag )

    if ( not hmac.compare_digest ( calculated_tag_hex, tag_hex.lower() ) ):
        raise ValueError ( "Authentication failed (HMAC mismatch)" )

    # hex IV -> bytes, base64 ciphertext -> bytes
    iv = hex_to_bytes ( iv_hex )
    if ( len ( iv ) != 16 ):
        raise ValueError ( "Invalid IV length" )

    ciphertext_binary = b64_decode_tolerant ( ciphertext_b64 )

    # AES-256-CBC decrypt
    return aes256_cbc_decrypt ( ciphertext_binary, aes_key, iv )

def main ( repetitor_id: str, port: int, print_semaphore: Semaphore ) -> None:
    configuration = get_configuration (
        CONTROLLER_HOST,
        CONTROLLER_PORT,
        CONTROLLER_GET_NONCE_PATH,
        CONTROLLER_REGISTER_PATH,
        CONTROLLER_CONFIGURATION_PATH,
        repetitor_id,
        f"127.0.0.1:{port}"  # Assuming the repetitor URL is the host
    )
    
    print_semaphore.acquire ( )
    print ( f"[{datetime.now():%H:%M:%S}][{repetitor_id}] configuration received:" )
    print ( json.dumps ( configuration, indent=4 ) )
    print_semaphore.release ( )
        
    ca_url_host    = configuration["ca_url_host"]
    ca_url_port    = configuration["ca_url_port"]
    ca_url_path    = configuration["ca_url_path"]
    left_kme       = configuration["left_kme"]
    right_kme      = configuration["right_kme"]
    left_cn        = configuration["left_cn"]
    right_cn       = configuration["right_cn"]
    left_kme_peer  = configuration["left_kme_peer"]
    right_kme_peer = configuration["right_kme_peer"]
    whitelist      = [item.strip ( ) for item in configuration["whitelist"].split ( "|" )]


    ca_url = f"http://{ca_url_host}:{ca_url_port}{ca_url_path}"

    repetitor_key, repetitor_certificate_pem = generate_certificate ( ca_url, repetitor_id )
    left_private_key, left_certificate_pem   = generate_certificate ( ca_url, left_cn )
    right_private_key, right_certificate_pem = generate_certificate ( ca_url, right_cn )

    if ( left_kme != "" ):
        status_response = kme_get_status (
            private_key = left_private_key,
            certificate = left_certificate_pem,
            ca_root_certificate = QKD_CA_CERTIFICATE,
            kme_host = left_kme,
            kme_port = KME_PORT,
            kme_slave = left_kme_peer 
        )

        if ( status_response.status_code != 200 ):
            raise Exception ( f"{repetitor_id}: Could not get status from left KME {left_kme}: {status_response.status_code} {status_response.text}" )

    if ( right_kme != "" ):
        status_response = kme_get_status (
            private_key = right_private_key,
            certificate = right_certificate_pem,
            ca_root_certificate = QKD_CA_CERTIFICATE,
            kme_host = right_kme,
            kme_port = KME_PORT,
            kme_slave = right_kme_peer 
        )

        if ( status_response.status_code != 200 ):
            raise Exception ( f"{repetitor_id}: Could not get status from right KME {right_kme}: {status_response.status_code} {status_response.text}" )

    left_repetitor_url  = configuration["left_repetitor_url"]
    right_repetitor_url = configuration["right_repetitor_url"]
    left_repetitor_id   = configuration["left_repetitor_id"]
    right_repetitor_id  = configuration["right_repetitor_id"]

    print_semaphore.acquire ( )
    position = None
    if ( left_kme == "" ):
        position = "left"
    elif ( right_kme == "" ):
        position = "right"
    else:
        position = "middle"
    print ( f"[{datetime.now():%H:%M:%S}][{repetitor_id}] position: {position}" )
    print_semaphore.release ( )

    while ( True ):
        subject, from_message_bytearray = receive_message (
            private_key = repetitor_key,
            certificate_pem = repetitor_certificate_pem,
            ca_certificate_pem = REPETITOR_CA_CERTIFICATE,
            host = "0.0.0.0",
            port = port,
            client_whitelist = whitelist,
            repetitor_id = repetitor_id
        )

        print_semaphore.acquire ( )
        print (f"[{datetime.now():%H:%M:%S}] {repetitor_id} received message: {from_message_bytearray.decode('utf-8')}")
        print_semaphore.release ( )
        
        from_url = left_repetitor_url if ( subject == left_repetitor_id ) else right_repetitor_url
        to_url   = right_repetitor_url if ( subject == left_repetitor_id ) else left_repetitor_url 

        kme_master = left_kme if ( subject == left_repetitor_id ) else right_kme
        kme_slave  = right_kme if ( subject == left_repetitor_id ) else left_kme

        kme_master_peer = left_kme_peer if ( subject == left_repetitor_id ) else right_kme_peer
        kme_slave_peer  = right_kme_peer if ( subject == left_repetitor_id ) else left_kme_peer

        kme_master_private_key = left_private_key if ( subject == left_repetitor_id ) else right_private_key
        kme_slave_private_key  = right_private_key if ( subject == left_repetitor_id ) else left_private_key

        kme_master_certificate = left_certificate_pem if ( subject == left_repetitor_id ) else right_certificate_pem
        kme_slave_certificate  = right_certificate_pem if ( subject == left_repetitor_id ) else left_certificate_pem

        print ( from_message_bytearray )
        print ( type ( from_message_bytearray ) )

        from_message = json.loads ( from_message_bytearray.decode ( "utf-8" ) );
        
        from_ciphertext = from_message["message"]
        from_key_id     = from_message["key_ID"]

        if ( kme_master != "" ):
            get_key_with_id_response = kme_get_key_with_id (
                private_key = kme_master_private_key,
                certificate = kme_master_certificate,
                ca_root_certificate = QKD_CA_CERTIFICATE,
                kme_host = kme_master,
                kme_port = KME_PORT,
                kme_master = kme_master_peer,
                key_id = from_key_id
            )

            from_key = get_key_with_id_response["keys"][0]["key"]

            plaintext = decrypt ( from_ciphertext, from_key )
            plaintext = plaintext.decode ( "utf-8" )
        else:
            plaintext = from_ciphertext

        print_semaphore.acquire ( )
        print ( f"[{datetime.now():%H:%M:%S}] {repetitor_id} decrypted message: {plaintext}" )
        print_semaphore.release ( )

        to_ciphertext = None
        to_key_id     = None

        if ( kme_slave != "" ):
            get_key_response = kme_get_key (
                private_key = kme_slave_private_key,
                certificate = kme_slave_certificate,
                ca_root_certificate = QKD_CA_CERTIFICATE,
                kme_host = kme_slave,
                kme_port = KME_PORT,
                kme_slave = kme_slave_peer
            )

            to_key_id = get_key_response["keys"][0]["key_ID"]
            to_key    = get_key_response["keys"][0]["key"]

            to_ciphertext = encrypt ( plaintext, to_key )
        else:
            to_ciphertext = plaintext
            to_key_id     = ""

        to_message = {
            "message": to_ciphertext,
            "key_ID": to_key_id
        }
        
        # print ( repetitor_certificate_pem )
        
        try:
            send_message (
                private_key = repetitor_key,
                certificate_pem = repetitor_certificate_pem,
                ca_certificate_pem = REPETITOR_CA_CERTIFICATE,
                host = to_url.split ( ":" )[0],
                port = int ( to_url.split ( ":" )[1] ),
                data = to_message
            )
        except Exception as e:
            print_semaphore.acquire ( )
            print ( f"[{datetime.now():%H:%M:%S}] {repetitor_id} error sending message to {to_url}: {e}" )
            print_semaphore.release ( )
        

if __name__ == "__main__":
    print_semaphore = Semaphore ( 1 )
    for i in [0, 2]:
        thread = Thread ( 
            target = main, 
            args = ( f"DR{i}", 9000 + i, print_semaphore )
        )

        thread.start ( )