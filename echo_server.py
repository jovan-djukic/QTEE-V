#!/usr/bin/env python3
"""
TLS Echo Server (ports 8999 & 8998) with certs issued by a local CFSSL server.

Requirements:
  pip install requests

CFSSL is expected to be running and reachable at http://127.0.0.1:8888
"""

import asyncio
import json
import ssl
import signal
import sys
from pathlib import Path

import requests

CFSSL_URL = "http://127.0.0.1:8888/api/v1/cfssl/newcert"
CERT_DIR = Path("./certs")
SERVER_CERT_PATH = CERT_DIR / "server.pem"
SERVER_KEY_PATH = CERT_DIR / "server-key.pem"
SERVER_CSR_PATH = CERT_DIR / "server.csr"
# Optional: if your CFSSL returns the issuer (CA) cert, we’ll write it here.
CA_CERT_PATH = CERT_DIR / "ca.pem"

HOSTS = ["localhost", "127.0.0.1"]
SERVER_CN = "test-client"
LISTEN_ADDR = "0.0.0.0"
PORTS = [8999, 8998]


def ensure_server_cert_from_cfssl ( ):
    """
    Requests a new certificate + private key from CFSSL /newcert and writes them to disk.
    If files already exist, this is a no-op.
    """
    CERT_DIR.mkdir ( parents=True, exist_ok=True )

    if ( SERVER_CERT_PATH.exists ( ) and SERVER_KEY_PATH.exists ( ) ):
        print ( f"[cert] Using existing certs at {SERVER_CERT_PATH} and {SERVER_KEY_PATH}" )
        return

    print ( "[cert] Requesting a new certificate from CFSSL..." )

    # This payload follows CFSSL's /newcert API: it generates the keypair and issues the cert server-side.
    # Ref: https://github.com/cloudflare/cfssl (API docs)
    payload = {
        "request": {
            "CN": SERVER_CN,
            "hosts": HOSTS,
            "key": {"algo": "rsa", "size": 2048},
            "names": [
                {
                    "C": "US",
                    "ST": "CA",
                    "L": "Local",
                    "O": "EchoServer",
                    "OU": "Dev",
                }
            ],
        }
        # Optionally include a profile, if your CFSSL is configured with named profiles:
        # "profile": "www"
    }

    try:
        response = requests.post ( 
            CFSSL_URL, 
            data = json.dumps ( payload ), 
            headers = {
                "Content-Type": "application/json"
            }, 
            timeout = 10
        )
    except requests.RequestException as error:
        print ( f"[cert] ERROR contacting CFSSL: {error}", file = sys.stderr )
        sys.exit(1)

    if ( response.status_code != 200 ):
        print ( f"[cert] CFSSL returned HTTP {response.status_code}: {response.text}", file = sys.stderr )
        sys.exit ( 1 )

    try:
        data = response.json ( )
    except ValueError:
        print ( f"[cert] Invalid JSON from CFSSL: {response.text[:500]}", file = sys.stderr )
        sys.exit ( 1 )

    if ( not data.get ( "success" ) ):
        print ( f"[cert] CFSSL error response: {data}", file = sys.stderr )
        sys.exit ( 1 )

    result   = data.get ( "result", {} )
    cert_pem = result.get ( "certificate" )
    key_pem  = result.get ( "private_key" )
    csr_pem  = result.get ( "certificate_request" )

    # Some CFSSL setups may include 'issuer' or similar. We'll capture it if present.
    ca_pem = result.get ( "issuer" ) or result.get ( "bundle" ) or result.get ( "ca" )

    if ( not cert_pem or not key_pem ):
        print ( f"[cert] Missing certificate or private_key in CFSSL response: {result}", file = sys.stderr )
        sys.exit ( 1 )

    SERVER_CERT_PATH.write_text ( 
        cert_pem if cert_pem.endswith ( "\n" ) else cert_pem + "\n", 
        encoding = "utf-8" 
    )

    SERVER_KEY_PATH.write_text ( 
        key_pem if key_pem.endswith ( "\n" ) else key_pem + "\n", 
        encoding = "utf-8" 
    )

    if ( csr_pem ):
        SERVER_CSR_PATH.write_text ( 
            csr_pem if csr_pem.endswith ( "\n" ) else csr_pem + "\n", 
            encoding = "utf-8"
        )

    # Write CA/issuer if present (handy for client verification during testing).
    if isinstance ( ca_pem, str ):
        CA_CERT_PATH.write_text ( 
            ca_pem if ca_pem.endswith ( "\n" ) else ca_pem + "\n", 
            encoding = "utf-8"
        )

    print ( f"[cert] Wrote {SERVER_CERT_PATH}, {SERVER_KEY_PATH}" + ( f", {SERVER_CSR_PATH}" if csr_pem else "" ) )
    if ( CA_CERT_PATH.exists ( ) ):
        print ( f"[cert] Wrote {CA_CERT_PATH}" )


def build_server_ssl_context ( ) -> ssl.SSLContext:
    """
    Prepares an SSL context for the server using the freshly issued cert and key.
    """
    context = ssl.create_default_context ( ssl.Purpose.CLIENT_AUTH )

    # By default we do NOT require client certificates (set to CERT_REQUIRED to enforce mTLS).
    context.verify_mode = ssl.CERT_NONE  # change to ssl.CERT_REQUIRED for mTLS
    context.load_cert_chain ( 
        certfile = str ( SERVER_CERT_PATH ), 
        keyfile = str ( SERVER_KEY_PATH )
    )

    # If you want to verify client certs (mTLS), uncomment below and set verify_mode above:
    # if CA_CERT_PATH.exists():
    #     ctx.load_verify_locations(cafile=str(CA_CERT_PATH))
    #     ctx.verify_mode = ssl.CERT_REQUIRED
    #     ctx.check_hostname = False

    return context


async def handle_echo(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    try:
        while True:
            # If you frame messages with \n, prefer readline(); otherwise read().
            data = await reader.read(4096)
            if not data:  # client performed orderly shutdown
                break

            # Echo back
            writer.write(data)
            print(data)
            try:
                await writer.drain()  # flush kernel buffer; may raise if peer closed
            except (BrokenPipeError, ConnectionResetError):
                # Peer went away while we were flushing the write buffer
                break

    except asyncio.CancelledError:
        # Task cancelled during shutdown – normal on server exit
        pass
    except (BrokenPipeError, ConnectionResetError):
        # Peer reset or closed mid-read/write – normal on abrupt client disconnects
        pass
    finally:
        try:
            writer.close()               # send TLS close_notify (for TLS) + close socket
            await writer.wait_closed()   # wait for transport to finish closing
        except Exception:
            pass
        print(f"[conn] closed {peer}")


async def start_servers ( ssl_context: ssl.SSLContext ):
    servers = []
    for port in PORTS:
        server = await asyncio.start_server ( handle_echo, LISTEN_ADDR, port, ssl = ssl_context )
        servers.append ( server )
        sockets = ", ".join ( str ( s.getsockname ( ) ) for s in server.sockets or [] )
        print ( f"[serve] TLS echo server listening on {sockets}" )
    return servers


async def amain ( ):
    ensure_server_cert_from_cfssl ( )
    ssl_context = build_server_ssl_context ( )
    servers = await start_servers ( ssl_context )

    # Graceful shutdown on SIGINT/SIGTERM
    stop = asyncio.Future ( )

    def _stop ( *_ ):
        if not stop.done ( ):
            stop.set_result ( True )

    loop = asyncio.get_running_loop ( )
    for signal_handler in ( signal.SIGINT, signal.SIGTERM ):
        try:
            loop.add_signal_handler ( signal_handler, _stop )
        except NotImplementedError:
            # Windows
            pass

    await stop
    for server in servers:
        server.close ( )
        await server.wait_closed ( )

    print ( "[serve] Shutdown complete." )


if ( __name__ == "__main__" ):
    try:
        asyncio.run ( amain ( ) )
    except KeyboardInterrupt:
        pass
