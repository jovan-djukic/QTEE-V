from typing import Union
from fastapi import FastAPI
from fastapi import HTTPException 
from fastapi import Response
from fastapi import Request 
from pydantic import BaseModel
from random import randbytes

from threading import Lock
from threading import Condition

import socket
from urllib.parse import urlsplit

application = FastAPI ( )

PYTHON_URL = "127.0.0.1"
RISCV_URL = "192.168.100.2"
CA_URL_PORT = "8888"
CA_URL_PATH = "/api/v1/cfssl/sign"

NONCE_DICTIONARY = { }
NONCE_DICTIONARY_LOCK = Lock ( )

LINKS = [
    {
        "start": "link0-left.acct-2563.etsi-qkd-api.qukaydee.com",
        "end": "link0-right.acct-2563.etsi-qkd-api.qukaydee.com",
        "start_sae": "link0-sae-left",
        "end_sae": "link0-sae-right",
    },
    {
        "start": "link1-left.acct-2563.etsi-qkd-api.qukaydee.com",
        "end": "link1-right.acct-2563.etsi-qkd-api.qukaydee.com",
        "start_sae": "link1-sae-left",
        "end_sae": "link1-sae-right",
    }
]

REPETITORS = [ 
    None,
    None,
    None
]

REPETITORS_LOCK = Lock ( )

CONFIGURATION_LOCK = Condition ( )



def url_to_ipv4 ( url ):
    """
    Converts a URL to its associated IPv4 address.
    """
    try:
        # 1. Extract the network location (hostname and optional port) from the URL
        split_url = urlsplit ( url )
        hostname = split_url.netloc
        
        # If the URL had no scheme (e.g., just "www.example.com"), netloc might be empty, 
        # so we use the path as the hostname instead.
        if ( not hostname ):
            hostname = split_url.path

        # Handle IPv6 hostnames in brackets (e.g., http://[::1]) by stripping them
        if ( hostname.startswith ( '[' ) and hostname.endswith ( ']' ) ):
            hostname = hostname.strip ( '[]' )

        # Strip the port if present
        if ( ':' in hostname and hostname.count ( ':' ) < 2 ): # Simple check to avoid confusing port with IPv6 notation
             hostname = hostname.split ( ':' )[0]
             
        # 2. Perform DNS resolution to get the IP address
        # socket.gethostbyname returns the IPv4 address string
        ipv4_address = socket.gethostbyname ( hostname )
        
        return ipv4_address
    except socket.gaierror:
        return f"Could not resolve the hostname for: {url}"
    except Exception as e:
        return f"An error occurred: {e}"

@application.get ( "/get_nonce" )
def register ( repetitor_id: Union[str, None] = None ):
    if ( repetitor_id == None ):
        return  HTTPException ( status_code = 400, detail = "Missing repetitor ID" )
    
    rand_bytes = randbytes ( 32 )

    NONCE_DICTIONARY_LOCK.acquire ( )
    NONCE_DICTIONARY[repetitor_id] = rand_bytes
    NONCE_DICTIONARY_LOCK.release ( )
    
    print ( f"[{repetitor_id}] Generated nonce: {rand_bytes.hex()}" )    

    return Response ( content = rand_bytes, media_type = "application/octet-stream" )

class RegisterModel ( BaseModel ):
    attestation_report: str
    repetitor_id: str
    repetitor_url: str

    def __repr__(self):
        return f"RegisterModel(attestation_report={self.attestation_report}, repetitor_id={self.repetitor_id}, repetitor_url={self.repetitor_url})"

def verify_attestation_report ( attestation_report, repetitor_id ):
    # always returns true
    return True


@application.post ( "/register" )
def register ( register_model:  RegisterModel, request: Request ):
    if ( register_model == None ):
        return  HTTPException (  status_code = 400, detail = "Missing attestation report" )
    
    if ( verify_attestation_report ( register_model.attestation_report, register_model.repetitor_id ) ):
        REPETITORS_LOCK.acquire ( )

        if ( register_model.repetitor_id not in REPETITORS ):
            index = int ( register_model.repetitor_id[-1] )
            REPETITORS[index] = {
                "repetitor_id": register_model.repetitor_id,
                "attestation_report": register_model.attestation_report,
                "repetitor_port": register_model.repetitor_url.split ( ":" )[-1],
            }

            print ( REPETITORS )
            with CONFIGURATION_LOCK:
                CONFIGURATION_LOCK.notify_all ( )

        REPETITORS_LOCK.release ( )

        print ( f"[{register_model.repetitor_id}] Registered successfully: {register_model}" )

        return {
            "status": "success",
            "message": "Repetitor registered successfully",
            "repetitor_id": register_model.repetitor_id,
        } 

    else:

        return HTTPException ( status_code = 400, detail = "Invalid attestation report" )
    
@application.post ( "/configuration" )
def configuration ( register_model:  RegisterModel, request: Request ):
    if ( register_model == None ):
        return  HTTPException (  status_code = 400, detail = "Missing attestation report" )

    if ( not verify_attestation_report ( register_model.attestation_report, register_model.repetitor_id ) ):
        return HTTPException ( status_code = 400, detail = "Invalid attestation report" )

    print ( f"HERE: {register_model}" )
    with CONFIGURATION_LOCK:
        # while ( len ( REPETITORS ) < len ( LINKS ) + 1 ):
        while ( any ( repetitor is None for repetitor in REPETITORS ) ):
            CONFIGURATION_LOCK.wait ( )

    index = None
    for i, repetitor in enumerate ( REPETITORS ):
        if ( repetitor["repetitor_id"] == register_model.repetitor_id ):
            index = i
            break
    
    # if ( register_model.repetitor_id == "DR0" ):
    #     index = 0
    # elif ( register_model.repetitor_id == "DR1" ):
    #     index = 1
    # elif ( register_model.repetitor_id == "DR2" ):
    #     index = 2
    
    if ( index is None ):
        return HTTPException ( status_code = 400, detail = "Repetitor not found" )
    
    print ( f"[{register_model.repetitor_id}] Configuration index: {index}" )
    
    base_url = RISCV_URL if ( "riscv" in register_model.repetitor_id ) else PYTHON_URL

    left_repetitor_port = REPETITORS[index - 1]["repetitor_port"] if ( index > 0 ) else "8998"

    right_repetitor_port = REPETITORS[index + 1]["repetitor_port"] if ( index < len ( REPETITORS ) - 1 ) else "8999"

    configuration = {
        # URL of CA
        "ca_url_host": base_url,
        "ca_url_port": CA_URL_PORT,
        "ca_url_path": CA_URL_PATH,

        # URL of left neighbour repetitor
        "left_repetitor_url": f"{base_url}:{left_repetitor_port}",

        # URL of right neighbour repetitor
        "right_repetitor_url": f"{base_url}:{right_repetitor_port}",

        # ID of left neighbour repetitor
        "left_repetitor_id": REPETITORS[index - 1]["repetitor_id"] if index > 0 else "test_client",

        # ID of right neighbour repetitor
        "right_repetitor_id": REPETITORS[index + 1]["repetitor_id"] if index < len(REPETITORS) - 1 else "test_client",

        # URL of left KME
        "left_kme": LINKS[index - 1]["end"] if ( index > 0 ) else "",

        # URL of right KME
        "right_kme": LINKS[index]["start"] if ( index < len(LINKS) ) else "",

        # ID of left neighboring SAE
        "left_cn": LINKS[index - 1]["end_sae"] if ( index > 0 ) else "test_client",

        # ID of right neighboring SAE
        "right_cn": LINKS[index]["start_sae"] if ( index < len(LINKS) ) else "test_client",

        # ID of left neighboring slave SAE
        "left_kme_peer": LINKS[index - 1]["start_sae"] if ( index > 0 ) else "",

        # ID of right neighboring slave SAE
        "right_kme_peer": LINKS[index]["end_sae"] if ( index < len(LINKS) ) else "",

        "whitelist": "|".join ( [ repetitor["repetitor_id"] for repetitor in REPETITORS if repetitor["repetitor_id"] != register_model.repetitor_id ] + [ "test_client" ] )
    }
    
    configuration["left_kme_url"] = url_to_ipv4 ( configuration["left_kme"] ) if ( configuration["left_kme"] != "" ) else ""
    configuration["right_kme_url"] = url_to_ipv4 ( configuration["right_kme"] ) if ( configuration["right_kme"] != "" ) else ""
    
    return configuration