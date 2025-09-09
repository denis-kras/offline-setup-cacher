#!/usr/bin/env python3
VERSION: str = '2.0.0'
# Exchanged the docker cache container to local code + Full rewrite.


import os
import ssl
import sys
import subprocess
from pathlib import Path
import threading
import socketserver
import http.server
import datetime
import re
import http.client
import pickle
import csv
import hashlib
from urllib.parse import urlparse
import shutil
import socket
import time
import argparse
import ipaddress
import textwrap
import shlex
from dataclasses import dataclass

import psutil
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from rich.console import Console


console = Console()


SCRIPT_DIRECTORY: str = os.path.dirname(os.path.realpath(__file__))
CACHE_DIRECTORY: str = str(Path(SCRIPT_DIRECTORY, 'cache'))
CERTS_DIRECTORY: str = str(Path(SCRIPT_DIRECTORY, 'certs'))
CLIENT_INSTALLATION_FILES_DIRECTORY: str = str(Path(SCRIPT_DIRECTORY, 'client_files'))

CERTS_SERVER_DIRECTORY: str = 'server_certs'
CERTS_CA_DIRECTORY: str = 'ca'
CA_CERT_FILE: str = str(Path(CERTS_CA_DIRECTORY, 'cache_ca.pem'))
CA_COMMON_NAME: str = "Proxy Server CA"
CERTIFICATES_SHARE_DIRECTORY: str = '/usr/local/share/ca-certificates'

CLIENT_INSTALL_FILE_NAME: str = 'client_install.sh'
CLIENT_UNINSTALL_FILE_NAME: str = 'client_uninstall.sh'

LOGS_DIRECTORY: str = str(Path(SCRIPT_DIRECTORY, 'logs'))

REQUESTS_CSV_PATH: str = str(Path(LOGS_DIRECTORY, 'requests_log.csv'))
CACHED_CSV_PATH: str = str(Path(LOGS_DIRECTORY, 'unique_cached_files.csv'))
REQUESTS_RESPONSES_LOG_PATH: str = str(Path(LOGS_DIRECTORY, 'full_requests_responses.log'))

log_lock = threading.Lock()
logged_cached = set()

ENABLE_FULL_LOG: bool = True
FULL_LOG_REQUEST_RESPONSE_TRUNCATION_LIMIT: int = 300

DUMMY_INTERFACE_CREATED: bool = False
GO_OFFLINE: bool = False


CLIENT_SCRIPT_DEFAULT_FLAGS: dict = {
    'h': 'Set HTTP/HTTPS proxy environment variables',
    'a': 'Set APT proxy configuration',
    'd': 'Set Docker daemon proxy configuration',
    'b': 'Set Docker BuildKit proxy configuration'
}
CLIENT_INSTALLATION_SCRIPT_DICT: dict = {
    'set_http': 'h',
    'set_apt': 'a',
    'set_docker_daemon': 'd',
    'set_docker_build': 'b',
}


@dataclass
class ParserDefaults:
    CA_CERT_FILE: str = None
    CACHE_DIR: str = None
    CERTS_DIR: str = None
    LISTEN_IP: str = None
    LISTEN_PORT: int = 3128
    LOCALHOST: bool = False
    CLIENT_FILES_DIR: str = None
    CLIENT_SCRIPT_OPTIONS: set = None
    WARM_APT_CACHE: bool = False
    GO_OFFLINE: bool = False


@dataclass
class DummyInterfaceConfig:
    INTERFACE_IP: str = '10.254.254.1'
    NAME: str = 'dummy0'
    AVAILABILITY_WAIT_SECONDS: int = 10


class NoInterfacesFoundError(Exception):
    """
    Exception raised when no network interfaces are found.
    """
    def __init__(self, message: str = "No network interfaces found."):
        super().__init__(message)


class MoreThanOneInterfaceFoundError(Exception):
    """
    Exception raised when more than one network interface is found.
    """
    def __init__(self, message: str = "More than one network interface found."):
        super().__init__(message)


class InterfaceArgumentsError(Exception):
    pass


def update_global_variables(
        cache_dir: str,
        certs_dir: str,
        ca_cert_file: str,
        client_files_dir: str
):
    """
    Update global variables for cache and certs directories.
    :param cache_dir: Cache directory path.
    :param certs_dir: Certs directory path.
    :param ca_cert_file: CA certificate file path.
    :param client_files_dir: Client installation files directory path.
    """
    global CACHE_DIRECTORY
    global CERTS_DIRECTORY
    global CLIENT_INSTALLATION_FILES_DIRECTORY
    global CERTS_SERVER_DIRECTORY
    global CERTS_CA_DIRECTORY
    global CA_CERT_FILE

    CACHE_DIRECTORY = cache_dir
    CERTS_DIRECTORY = certs_dir
    CERTS_SERVER_DIRECTORY = str(Path(CERTS_DIRECTORY, CERTS_SERVER_DIRECTORY))
    CERTS_CA_DIRECTORY = str(Path(CERTS_DIRECTORY, CERTS_CA_DIRECTORY))

    if not ca_cert_file:
        CA_CERT_FILE = str(Path(CERTS_DIRECTORY, CA_CERT_FILE))
    else:
        CA_CERT_FILE = ca_cert_file

    if client_files_dir:
        CLIENT_INSTALLATION_FILES_DIRECTORY = client_files_dir


def remove_dummy_interface():
    if DUMMY_INTERFACE_CREATED:
        print("[+] Removing dummy interface...")
        subprocess.check_call(shlex.split("sudo rm -f /etc/systemd/network/10-proxy.netdev /etc/systemd/network/20-proxy.network"))
        subprocess.check_call(shlex.split("sudo systemctl daemon-reload"))
        subprocess.check_call(shlex.split("sudo systemctl restart systemd-networkd"))

        # If the link is still present, delete it (ignore if it's already gone)
        exists = subprocess.run(["ip", "link", "show", DummyInterfaceConfig.NAME],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
        if exists:
            subprocess.run(["sudo", "ip", "link", "del", DummyInterfaceConfig.NAME], check=False)

        print("[+] Dummy interface removed.")

    if GO_OFFLINE:
        subprocess.check_call(shlex.split("sudo ip route del blackhole default"))
        print("[+] Connectivity restored.")


def _run_and_stream(
        cmd: list,
        env=None,
        prefix: str = "[stream] "
):
    """
    Run a command and stream its output to stdout, line by line, stripping the ANSI control codes and replace '\r' with '\n'.
    :param cmd: list, command and arguments to run.
    :param env: dict, environment variables to set for the command.
    :param prefix: str, prefix to add to each line of output.
        Example: if you run 'apt update', you can set prefix='[apt] ' to distinguish the output.
    :return:
    """
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,   # apt writes progress to stderr; merge it.
        text=True,
        bufsize=1,
        env=env,
    )

    ansi = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")  # strip color/controls
    try:
        while True:
            chunk = proc.stdout.read(1024)
            if not chunk:
                break
            chunk = chunk.replace("\r", "\n")      # break overprinted lines
            chunk = ansi.sub("", chunk)            # remove ANSI escapes
            for line in chunk.splitlines():
                if line:
                    print(f"{prefix}{line}", flush=True)
    finally:
        proc.stdout.close()
        rc = proc.wait()
        if rc != 0:
            raise subprocess.CalledProcessError(rc, cmd)


def run_full_apt_update(
        proxy_ip: str,
        proxy_port: int,
):
    """
    The function removes current apt indexes and downloads the full set of indexes without diffs.

    :param proxy_ip: Proxy server IP address.
    :param proxy_port: Proxy server port.
    :return: None
    """

    # Make apt/dpkg behave nicely in non-interactive scripts.
    env = os.environ.copy()
    env.update({
        "DEBIAN_FRONTEND": "noninteractive",
        "TERM": "dumb",  # disables fancy progress rendering
        "LC_ALL": "C",
    })

    # Delete current apt indexes.
    subprocess.run(["sudo", "sh", "-c", "rm -rf /var/lib/apt/lists/*"], check=True)

    # Update full indexes using the current proxy.
    proxy = f"http://{proxy_ip}:{str(proxy_port)}"
    cmd = [
        "sudo", "apt", "update",
        "-o", "Acquire::PDiffs=false",
        "-o", f"Acquire::http::Proxy={proxy}",
        "-o", f"Acquire::https::Proxy={proxy}",
        # Adding these so there will be as much less pat output as possible, since it adds '\r' characters. and garbles the total output.
        "-o", "APT::Color=0",
        "-o", "Dpkg::Progress-Fancy=0",
        "-qq",
    ]
    # subprocess.run(cmd, check=True)
    _run_and_stream(cmd, env=env, prefix="[apt] ")
    console.print("[+] Full apt update completed.", style="green")


def create_ca_certificates():
    """
    Function creates a self-signed CA PEM certificate and private key.

    :return:
    """

    # Generate a 2048-bit RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Define subject and issuer (self-signed)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, CA_COMMON_NAME),
    ])

    # Build a self-signed certificate valid for 3650 days
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650))
        # Add basic constraints extension indicating a CA certificate
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())
    )

    # Write the private key and certificate to a PEM file (squidCA.pem)
    with open(CA_CERT_FILE, "wb") as pem_file:
        pem_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
        pem_file.write(certificate.public_bytes(serialization.Encoding.PEM))


def create_crt_and_der_from_pem():
    """
    Function creates DER and CRT files from the PEM file.
    The PEM file is expected to contain multiple PEM objects.
    The function extracts the first certificate block and writes it to squidCA.der and squidCA.crt files.
    :return:
    """
    def extract_certificate_from_pem(pem_file_data: bytes) -> bytes:
        """
        Extracts the first certificate block from a PEM file that contains multiple PEM objects.
        """
        start_marker = b"-----BEGIN CERTIFICATE-----"
        end_marker = b"-----END CERTIFICATE-----"
        start_index = pem_file_data.find(start_marker)
        if start_index == -1:
            raise ValueError("Certificate block not found in PEM file.")
        end_index = pem_file_data.find(end_marker, start_index)
        if end_index == -1:
            raise ValueError("End of certificate block not found in PEM file.")
        end_index += len(end_marker)
        return pem_file_data[start_index:end_index]

    with open(CA_CERT_FILE, "rb") as pem_file:
        pem_data = pem_file.read()

    # Extract the certificate block from the combined PEM file
    cert_pem = extract_certificate_from_pem(pem_data)
    certificate = x509.load_pem_x509_certificate(cert_pem)

    ca_pem_path_object: Path = Path(CA_CERT_FILE)

    # Write the certificate in DER format to squidCA.der
    ca_der_file_path: str = str(ca_pem_path_object.parent) + os.sep + ca_pem_path_object.stem + ".der"
    with open(ca_der_file_path, "wb") as der_file:
        der_file.write(certificate.public_bytes(serialization.Encoding.DER))

    # Write the certificate in PEM format to squidCA.crt
    ca_crt_file_path: str = str(ca_pem_path_object.parent) + os.sep + ca_pem_path_object.stem + ".crt"
    with open(ca_crt_file_path, "wb") as crt_file:
        crt_file.write(certificate.public_bytes(serialization.Encoding.PEM))

    print("[+] CA Certificates generated.")


def log_full_pair(req_text, resp_text):
    """Append a full request/response pair to the log file."""
    with open(REQUESTS_CSV_PATH, "a", encoding="utf-8") as f:
        f.write("=== Request ===\n")
        f.write(req_text)
        f.write("\n=== Response ===\n")
        f.write(resp_text)
        f.write("\n================\n\n")


def load_ca_cert_and_key(ca_cert_file: str, ca_key_file: str = None):
    """
    Load CA certificate and key. If ca_key_file is provided, it is used for the key;
    otherwise, the function assumes both are in the same file.
    """
    with open(ca_cert_file, "rb") as f:
        cert_data = f.read()

    if ca_key_file:
        with open(ca_key_file, "rb") as f:
            key_data = f.read()
    else:
        # If no separate key file is provided, assume both cert and key are in ca_cert_file.
        key_data = cert_data

    key_pattern = re.compile(
        b'-----BEGIN (?:RSA )?PRIVATE KEY-----.*?-----END (?:RSA )?PRIVATE KEY-----',
        re.DOTALL)
    cert_pattern = re.compile(
        b'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',
        re.DOTALL)
    key_match = key_pattern.search(key_data)
    cert_matches = cert_pattern.findall(cert_data)
    if key_match is None or not cert_matches:
        raise ValueError("Failed to parse CA certificate or key from provided file(s)")
    ca_key_data = key_match.group(0)
    ca_cert_data = cert_matches[0]

    ca_private_key = load_pem_private_key(ca_key_data, password=None)
    ca_cert = x509.load_pem_x509_certificate(ca_cert_data)
    return ca_cert, ca_private_key


def get_or_create_cert(host, ca_file, certs_dir):
    cert_file = os.path.join(certs_dir, f"{host}.pem")
    if os.path.exists(cert_file):
        return cert_file
    ca_cert, ca_private_key = load_ca_cert_and_key(ca_file)
    host_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    issuer = ca_cert.subject
    now = datetime.datetime.now(datetime.timezone.utc)
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(host_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    )
    host_cert = cert_builder.sign(private_key=ca_private_key, algorithm=hashes.SHA256())
    with open(cert_file, "wb") as f:
        f.write(host_cert.public_bytes(serialization.Encoding.PEM))
        f.write(host_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    print(f"Generated certificate for {host} and stored in {cert_file}")
    return cert_file


def _serve_offline_token(handler):
    """
    Reply to any /token?… request when we are offline (or chose not to cache tokens).

    A tiny static token is enough for Docker Engine to continue the pull.
    """
    body = b'{"token":"offline","access_token":"offline"}'
    handler.send_response(200)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def generate_cache_key(
        method: str,
        url: str,
) -> str:
    """
    Generate SHA-256 hash as the cache key.

    :param method: string, the HTTP method (e.g., "GET", "HEAD").
    :param url: string, the url to generate the key for.
    """

    parsed = urlparse(url)

    # Build the canonical part common to all requests.
    normalized = parsed.netloc + parsed.path

    # For everything that isn’t a registry-manifest keep the query
    if parsed.query:
        normalized += "?" + parsed.query

    # Prepend the HTTP method and (optionally) Accept header,
    # so HEAD ≠ GET and OCI ≠ Docker schema                          #
    h = hashlib.sha256()
    h.update(method.upper().encode())  # "GET", "HEAD", ...
    h.update(b"\x00")
    h.update(normalized.encode())

    return h.hexdigest()


def append_cached_log(url, file_name, file_hash):
    """Append a unique entry to cached.csv: url, file_name, sha256"""
    with log_lock:
        if file_name not in logged_cached:
            file_exists = os.path.exists(CACHED_CSV_PATH)
            with open(CACHED_CSV_PATH, 'a', newline='') as csvfile:
                writer = csv.writer(csvfile)
                if not file_exists:
                    writer.writerow(["url", "file_name", "sha256"])
                writer.writerow([url, file_name, file_hash])
            logged_cached.add(file_name)


def append_request_log(time_str, source_ip, method, url, port, status_code, file_name, file_hash):
    """
    Append a request entry to requests.csv with columns:
    time, source_ip, method, url, port, status_code, file_name, sha256
    """
    with log_lock:
        file_exists = os.path.exists(REQUESTS_CSV_PATH)
        with open(REQUESTS_CSV_PATH, 'a', newline='') as csvfile:
            writer = csv.writer(csvfile)
            if not file_exists:
                writer.writerow(["time", "source_ip", "method", "url", "port", "status_code", "file_name", "sha256"])
            writer.writerow([time_str, source_ip, method, url, port, status_code, file_name, file_hash])


def should_write_cache(status: int, path: str) -> bool:
    # Cache successes and redirects unconditionally
    if status < 400:
        return True
    # The one exception: we want the 401 challenge on /v2/
    return status == 401 and path == "/v2/"


class MitmHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    # noinspection PyPep8Naming
    def do_GET(self):
        parsed = urlparse(self.path)
        # host = self.headers.get('Host')
        # domain, _, port = host.partition(':')

        # ------------------------------------------------------------------ #
        # Build the target connection & a unique cache key                 #
        # ------------------------------------------------------------------ #
        if parsed.scheme == "http":
            conn = http.client.HTTPConnection(parsed.netloc)
            target_port = 80
        elif parsed.scheme == "https":
            conn = http.client.HTTPSConnection(parsed.netloc)
            target_port = 443
        else:
            target_host = self.headers.get("Host", "unknown_host")
            conn = http.client.HTTPSConnection(target_host)
            target_port = 443

        if parsed.scheme in ["http", "https"]:
            full_url = parsed.netloc + parsed.path + ("?" + parsed.query if parsed.query else "")
        else:
            full_url = self.headers.get("Host", "unknown_host") + self.path

        is_token_request: bool = "auth.docker.io/token" in full_url
        safe_key = generate_cache_key(method=self.command, url=full_url)
        cache_file = os.path.join(CACHE_DIRECTORY, safe_key)

        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        source_ip = self.client_address[0]

        # Prepare full request log text.
        req_text = f"{self.requestline}\n{self.headers}"

        # ------------------------------------------------------------------ #
        # Serve from cache *only* when it is NOT a token request           #
        # ------------------------------------------------------------------ #
        if os.path.exists(cache_file) and not is_token_request:
            with open(cache_file, 'rb') as f:
                cached_response = pickle.load(f)

            self._relay(cached_response)

            # file_hash = hashlib.sha256(cached_response['body']).hexdigest()
            append_cached_log(full_url, safe_key, cached_response['sha256'])
            append_request_log(timestamp, source_ip, self.command, full_url, target_port, cached_response['status'], safe_key, cached_response['sha256'])
            resp_text = (f"Status: {cached_response['status']} {cached_response['reason']}\n"
                         f"Headers: {cached_response['headers']}\n"
                         f"Body (first {str(FULL_LOG_REQUEST_RESPONSE_TRUNCATION_LIMIT)} bytes): "
                         f"{cached_response['body'][:FULL_LOG_REQUEST_RESPONSE_TRUNCATION_LIMIT]!r} (total {len(cached_response['body'])} bytes)")
                         # f"Body: {cached_response['body']!r}")
            if ENABLE_FULL_LOG:
                log_full_pair(req_text, resp_text)
            print(f"Served cached GET response from {cache_file}")
            return

        # ------------------------------------------------------------------ #
        # Forward to the real origin                                       #
        # ------------------------------------------------------------------ #
        try:
            conn.request(self.command, parsed.path + ("?" + parsed.query if parsed.query else ""), headers=self.headers)
            remote_response = conn.getresponse()
            body = remote_response.read()
        except Exception as e:
            _ = e
            # ---------------------- offline / error branch ---------------- #
            if is_token_request:
                _serve_offline_token(self)  # never cached
                return

            if os.path.exists(cache_file):  # fall back to stale artefact
                with open(cache_file, "rb") as f:
                    cached_response = pickle.load(f)
                self._relay(cached_response)
                if ENABLE_FULL_LOG:
                    log_full_pair(req_text, "(network error – served stale cache)")
                print(f"Network error; served cached GET response from {cache_file}")
                return

            self.send_error(502, "Origin fetch failed and no cache available")
            return
        finally:
            conn.close()

        # ------------------------------------------------------------------ #
        # Relay live response – cache it unless it is a token             #
        # ------------------------------------------------------------------ #
        self.send_response(remote_response.status, remote_response.reason)
        for hdr, val in remote_response.getheaders():
            if hdr.lower() == "transfer-encoding":
                continue
            self.send_header(hdr, val)
        if "content-length" not in {h.lower() for h, _ in remote_response.getheaders()}:
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

        if (not is_token_request) and should_write_cache(remote_response.status, parsed.path):
            # write-through cache
            # noinspection PyTypeChecker
            pickle.dump(
                {
                    "status": remote_response.status,
                    "reason": remote_response.reason,
                    "headers": remote_response.getheaders(),
                    "body": body,
                    "sha256": hashlib.sha256(body).hexdigest(),
                },
                open(cache_file, "wb")
            )
            append_cached_log(full_url, safe_key, hashlib.sha256(body).hexdigest())

        append_request_log(timestamp, source_ip, "GET",
                           full_url, target_port, remote_response.status,
                           "" if is_token_request else safe_key,
                           "" if is_token_request else hashlib.sha256(body).hexdigest())

        if ENABLE_FULL_LOG:
            body_preview = body[:FULL_LOG_REQUEST_RESPONSE_TRUNCATION_LIMIT]
            log_full_pair(
                req_text,
                f"Status: {remote_response.status}; body preview ({len(body)} bytes): {body_preview!r}"
            )

        print(f"Forwarded GET {self.path} with response {remote_response.status}")

    # noinspection PyPep8Naming
    def do_HEAD(self):
        parsed = urlparse(self.path)
        if parsed.scheme in ["http", "https"]:
            full_url = parsed.netloc + parsed.path + ("?" + parsed.query if parsed.query else "")
        else:
            full_url = self.headers.get("Host", "unknown_host") + self.path
        safe_key = generate_cache_key(method=self.command, url=full_url)
        cache_file = os.path.join(CACHE_DIRECTORY, safe_key)

        # (Optional) Prepare full log text.
        req_text = f"{self.requestline}\n{self.headers}"

        # If a cached GET response exists, serve its headers.
        if os.path.exists(cache_file):
            with open(cache_file, 'rb') as f:
                cached_response = pickle.load(f)
            self.send_response(cached_response['status'], cached_response['reason'])
            for header, value in cached_response['headers']:
                if header.lower() == "transfer-encoding":
                    continue
                self.send_header(header, value)
            self.end_headers()
            resp_text = (f"Status: {cached_response['status']} {cached_response['reason']}\n"
                         f"Headers: {cached_response['headers']}")
            if ENABLE_FULL_LOG:
                log_full_pair(req_text, resp_text)
            print(f"Served cached HEAD response from {cache_file}")
            return

        try:
            if parsed.scheme == "http":
                conn = http.client.HTTPConnection(parsed.netloc)
                target_path = parsed.path + ("?" + parsed.query if parsed.query else "")
            elif parsed.scheme == "https":
                conn = http.client.HTTPSConnection(parsed.netloc)
                target_path = parsed.path + ("?" + parsed.query if parsed.query else "")
            else:
                target_host = self.headers.get("Host", "unknown_host")
                conn = http.client.HTTPSConnection(target_host)
                target_path = self.path

            conn.request("HEAD", target_path, headers=self.headers)
            remote_response = conn.getresponse()

            if remote_response.status == 304 and os.path.exists(cache_file):
                # Serve the existing object; don't touch the cache file
                with open(cache_file, 'rb') as f:
                    cached_response = pickle.load(f)
                self._relay(cached_response)  # helper that sends status/headers/body
                return
            # If live HEAD returns 401 Unauthorized and a cached GET response exists, serve cache.
            if remote_response.status == 401 and os.path.exists(cache_file):
                with open(cache_file, 'rb') as f:
                    cached_response = pickle.load(f)
                self.send_response(cached_response['status'], cached_response['reason'])
                for header, value in cached_response['headers']:
                    if header.lower() == "transfer-encoding":
                        continue
                    self.send_header(header, value)
                self.end_headers()
                resp_text = (f"Status: {cached_response['status']} {cached_response['reason']}\n"
                             f"Headers: {cached_response['headers']}")
                if ENABLE_FULL_LOG:
                    log_full_pair(req_text, resp_text)
                print(f"Live HEAD returned 401; served cached HEAD response from {cache_file}")
                return

            # Otherwise, serve the live HEAD response.
            self.send_response(remote_response.status, remote_response.reason)
            for header, value in remote_response.getheaders():
                if header.lower() == "transfer-encoding":
                    continue
                self.send_header(header, value)
            self.end_headers()

            # Write-through cache (body is empty – that is fine for HEAD)
            if should_write_cache(remote_response.status, parsed.path):
                # noinspection PyTypeChecker
                pickle.dump(
                    {
                        "status": remote_response.status,
                        "reason": remote_response.reason,
                        "headers": list(remote_response.getheaders()),
                        "body": b"",  # empty body in a HEAD reply
                        "sha256": "",
                    },
                    open(cache_file, "wb")
                )
                append_cached_log(full_url, safe_key, "")

            conn.close()
            resp_text = (f"Status: {remote_response.status} {remote_response.reason}\n"
                         f"Headers: {remote_response.getheaders()}")
            if ENABLE_FULL_LOG:
                log_full_pair(req_text, resp_text)
        except Exception as e:
            # Network error – try to serve from cache instead of returning 502    #
            # exact HEAD key
            if os.path.exists(cache_file):
                with open(cache_file, "rb") as f:
                    cached = pickle.load(f)
                self._relay(cached)
                print(f"Network error; served cached HEAD response from {cache_file}")
                return

            # fallback to corresponding cached GET (same URL, Accept etc.)
            get_key = generate_cache_key("GET", full_url)
            get_file = os.path.join(CACHE_DIRECTORY, get_key)
            if os.path.exists(get_file):
                with open(get_file, "rb") as f:
                    cached_get = pickle.load(f)

                # synthesise a headers-only reply
                cached_head = {
                    "status": 200,
                    "reason": "OK",
                    "headers": [
                                   (h, v) for h, v in cached_get["headers"]
                                   if h.lower() not in ("content-length", "transfer-encoding")
                               ] + [("Content-Length", "0")],
                    "body": b"",
                    "sha256": cached_get.get("sha256", ""),
                }
                self._relay(cached_head)
                print(f"Network error; served HEAD derived from cached GET {get_file}")
                return

            # nothing cached - real error
            self.send_error(502, f"Origin fetch failed and no cache available ({e})")
            return

    # noinspection PyPep8Naming
    def do_CONNECT(self):
        try:
            target_host, target_port = self.path.split(":")
            target_port = int(target_port)
        except Exception as e:
            self.send_error(400, f"Bad CONNECT request: {e}")
            return
        req_text = f"{self.requestline}\n{self.headers}"
        self.send_response(200, "Connection Established")
        self.end_headers()
        try:
            host_cert_file = get_or_create_cert(target_host, CA_CERT_FILE, CERTS_SERVER_DIRECTORY)
            mitm_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            mitm_context.load_cert_chain(certfile=host_cert_file)
            ssl_conn = mitm_context.wrap_socket(self.connection, server_side=True)
        except Exception as e:
            print("SSL handshake with client failed:", e)
            return
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        source_ip = self.client_address[0]
        method = "CONNECT"
        append_request_log(timestamp, source_ip, method, self.path, target_port, 200, "", "")
        resp_text = "Status: 200 Connection Established"
        if ENABLE_FULL_LOG:
            log_full_pair(req_text, resp_text)
        self.connection = ssl_conn
        # noinspection PyTypeChecker
        self.rfile = ssl_conn.makefile('rb', buffering=0)
        # noinspection PyTypeChecker
        self.wfile = ssl_conn.makefile('wb', buffering=0)

        while True:
            try:
                # reset so HTTP/1.1 keep-alive works
                self.close_connection = False
                self.handle_one_request()  # parse & serve one HTTP msg
                if self.close_connection:  # set by the base class
                    break  # • “Connection: close”
                    #   • end of stream
            except Exception as e:
                _ = e
                break  # socket closed, TLS alert, etc.

    # noinspection PyPep8Naming
    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.scheme == "http":
            conn = http.client.HTTPConnection(parsed.netloc)
            target_port = 80
        elif parsed.scheme == "https":
            conn = http.client.HTTPSConnection(parsed.netloc)
            target_port = 443
        else:
            target_host = self.headers.get("Host", "unknown_host")
            conn = http.client.HTTPSConnection(target_host)
            target_port = 443
        try:
            content_length = int(self.headers.get('Content-Length', 0))
        except Exception as e:
            _ = e
            content_length = 0
        post_body = self.rfile.read(content_length) if content_length > 0 else b''
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        source_ip = self.client_address[0]
        method = "POST"
        if parsed.scheme in ["http", "https"]:
            url_to_log = parsed.netloc + parsed.path + ("?" + parsed.query if parsed.query else "")
        else:
            url_to_log = self.path
        req_text = f"{self.requestline}\n{self.headers}\nBody: {post_body[:FULL_LOG_REQUEST_RESPONSE_TRUNCATION_LIMIT]!r} (total {len(post_body)} bytes)"
        if "git-upload-pack" in self.path:
            if parsed.scheme in ["http", "https"]:
                base = parsed.netloc + parsed.path
                if parsed.query:
                    base += "?" + parsed.query
            else:
                base = self.headers.get("Host", "unknown_host") + self.path

            key_bytes = base.encode('utf-8') + post_body
            safe_key = hashlib.sha256(key_bytes).hexdigest()
            cache_file = os.path.join(CACHE_DIRECTORY, safe_key)
            if os.path.exists(cache_file):
                with open(cache_file, 'rb') as f:
                    cached_response = pickle.load(f)
                self.send_response(cached_response['status'], cached_response['reason'])
                for header, value in cached_response['headers']:
                    if header.lower() == "transfer-encoding":
                        continue
                    self.send_header(header, value)
                if not any(header.lower() == "content-length" for header, _ in cached_response['headers']):
                    self.send_header("Content-Length", str(len(cached_response['body'])))
                self.end_headers()
                self.wfile.write(cached_response['body'])
                file_hash = hashlib.sha256(cached_response['body']).hexdigest()
                append_request_log(timestamp, source_ip, method, url_to_log, target_port, cached_response['status'], safe_key, file_hash)
                resp_text = (f"Status: {cached_response['status']} {cached_response['reason']}\n"
                             f"Headers: {cached_response['headers']}\n"
                             f"Body (first {str(FULL_LOG_REQUEST_RESPONSE_TRUNCATION_LIMIT)} bytes): {cached_response['body'][:FULL_LOG_REQUEST_RESPONSE_TRUNCATION_LIMIT]!r} (total {len(cached_response['body'])} bytes)")
                             # f"Body: {cached_response['body']!r}")
                if ENABLE_FULL_LOG:
                    log_full_pair(req_text, resp_text)
                print(f"Served cached POST response from {cache_file}")
                return
            try:
                conn.request("POST", parsed.path + ("?" + parsed.query if parsed.query else ""), body=post_body, headers=self.headers)
                remote_response = conn.getresponse()
                body = remote_response.read()
                conn.close()
                cached_response = {
                    "status": remote_response.status,
                    "reason": remote_response.reason,
                    "headers": list(remote_response.getheaders()),
                    "body": body,
                }
                with open(cache_file, 'wb') as f:
                    # noinspection PyTypeChecker
                    pickle.dump(cached_response, f)
                self.send_response(remote_response.status, remote_response.reason)
                for header, value in remote_response.getheaders():
                    if header.lower() == "transfer-encoding":
                        continue
                    self.send_header(header, value)
                if not any(header.lower() == "content-length" for header, _ in remote_response.getheaders()):
                    self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                file_hash = hashlib.sha256(body).hexdigest()
                append_request_log(timestamp, source_ip, method, url_to_log, target_port, remote_response.status, safe_key, file_hash)
                resp_text = (f"Status: {remote_response.status} {remote_response.reason}\n"
                             f"Headers: {remote_response.getheaders()}\n"
                             f"Body (first {str(FULL_LOG_REQUEST_RESPONSE_TRUNCATION_LIMIT)} bytes): "
                             f"{body[:FULL_LOG_REQUEST_RESPONSE_TRUNCATION_LIMIT]!r} (total {len(body)} bytes)")
                             # f"Body: {body!r}")
                if ENABLE_FULL_LOG:
                    log_full_pair(req_text, resp_text)
                print(f"Fetched and cached new POST response to {cache_file}")
            except Exception as e:
                if os.path.exists(cache_file):
                    with open(cache_file, 'rb') as f:
                        cached_response = pickle.load(f)
                    self.send_response(cached_response['status'], cached_response['reason'])
                    for header, value in cached_response['headers']:
                        if header.lower() == "transfer-encoding":
                            continue
                        self.send_header(header, value)
                    if not any(header.lower() == "content-length" for header, _ in cached_response['headers']):
                        self.send_header("Content-Length", str(len(cached_response['body'])))
                    self.end_headers()
                    self.wfile.write(cached_response['body'])
                    file_hash = hashlib.sha256(cached_response['body']).hexdigest()
                    append_request_log(timestamp, source_ip, method, url_to_log, target_port, cached_response['status'], safe_key, file_hash)
                    resp_text = (f"Status: {cached_response['status']} {cached_response['reason']}\n"
                                 f"Headers: {cached_response['headers']}\n"
                                 f"Body (first {str(FULL_LOG_REQUEST_RESPONSE_TRUNCATION_LIMIT)} bytes): "
                                 f"{cached_response['body'][:FULL_LOG_REQUEST_RESPONSE_TRUNCATION_LIMIT]!r} (total {len(cached_response['body'])} bytes)")
                                 # f"Body: {cached_response['body']!r}")
                    if ENABLE_FULL_LOG:
                        log_full_pair(req_text, resp_text)
                    print(f"Network error; served cached POST response from {cache_file}")
                else:
                    self.send_error(502, f"Error fetching remote server: {e}")
                    append_request_log(timestamp, source_ip, method, url_to_log, target_port, "", "", "")
        else:
            try:
                conn.request("POST", parsed.path + ("?" + parsed.query if parsed.query else ""), body=post_body, headers=self.headers)
                remote_response = conn.getresponse()
                body = remote_response.read()
                conn.close()
                self.send_response(remote_response.status, remote_response.reason)
                for header, value in remote_response.getheaders():
                    if header.lower() == "transfer-encoding":
                        continue
                    self.send_header(header, value)
                if not any(header.lower() == "content-length" for header, _ in remote_response.getheaders()):
                    self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                append_request_log(timestamp, source_ip, method, url_to_log, target_port, remote_response.status, "", "")
                resp_text = (f"Status: {remote_response.status} {remote_response.reason}\n"
                             f"Headers: {remote_response.getheaders()}\n"
                             f"Body (first {str(FULL_LOG_REQUEST_RESPONSE_TRUNCATION_LIMIT)} bytes): "
                             f"{body[:FULL_LOG_REQUEST_RESPONSE_TRUNCATION_LIMIT]!r} (total {len(body)} bytes)")
                             # f"Body: {body!r}")
                if ENABLE_FULL_LOG:
                    log_full_pair(req_text, resp_text)
                print(f"Forwarded POST {self.path} with response {remote_response.status}")
            except Exception as e:
                self.send_error(502, f"Error fetching remote server: {e}")
                append_request_log(timestamp, source_ip, method, url_to_log, target_port, "", "", "")

    def _relay(self, cached: dict) -> None:
        """
        Emit a cached response to the client.

        cached keys:
            status  (int)
            reason  (str)
            headers (list[tuple[str, str]])
            body    (bytes)
            sha256  (str)   # optional, for logging only
        """
        # ---------- status line -------------------------------------------------
        self.send_response(cached["status"], cached["reason"])

        # ---------- headers -----------------------------------------------------
        sent_headers = set()
        for hdr, val in cached["headers"]:
            h_lower = hdr.lower()

            # Drop the original Transfer-Encoding; we send a complete body.
            if h_lower == "transfer-encoding":
                continue

            self.send_header(hdr, val)
            sent_headers.add(h_lower)

        # If TE was stripped or the origin used chunked encoding, be sure we have
        # a definite length so the client knows when the body ends.
        if "content-length" not in sent_headers:
            self.send_header("Content-Length", str(len(cached["body"])))

        self.end_headers()

        # ---------- body (skip for HEAD) ----------------------------------------
        if self.command != "HEAD":
            self.wfile.write(cached["body"])

    # noinspection PyShadowingBuiltins
    def log_message(self, format, *args):
        print("%s - - [%s] %s" %
              (self.client_address[0],
               self.log_date_time_string(),
               format % args))

class ThreadedTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


def run_proxy_server(
        listen_ip: str = "0.0.0.0",
        listen_port: int = ParserDefaults.LISTEN_PORT
):
    """
    Run the main HTTP/HTTPS proxy server on the specified port.

    :param listen_ip: string, IP address to bind the server to (default is "0.0.0.0" for all interfaces).
    :param listen_port: integer, Port for the proxy server.
    """

    # Passing "" as the first argument will bind to all interfaces, like 0.0.0.0
    # noinspection PyTypeChecker
    server = ThreadedTCPServer((listen_ip, listen_port), MitmHTTPRequestHandler)
    # print(f"MITM caching proxy server running on: {listen_ip}:{listen_port}")
    server.serve_forever()


def create_client_installation_files(
        proxy_ip: str,
        proxy_port: int,

        set_http: bool = True,
        set_apt: bool = True,
        set_docker_daemon: bool = True,
        set_docker_build: bool = True
):
    """
    Create client installation scripts for setting up the proxy environment on the client.

    :param proxy_ip: str, the IP address of the proxy server.
    :param proxy_port: int, the port on which the proxy server is listening.

    :param set_http: bool, whether to set HTTP/HTTPS proxy environment variables.
    :param set_apt: bool, whether to set APT proxy configuration, including HTTP/HTTPS proxy.
    :param set_docker_daemon: bool, whether to set Docker daemon proxy configuration.
    :param set_docker_build: bool, whether to set proxy for the BuildKit container that creates a docker image
        while using the docker [build command], also the CA certificate will be added+registered to the created image.
    :return:
    """



    if set_http + set_apt + set_docker_daemon + set_docker_build == 0:
        raise ValueError("At least one of the 'set_*' attributes must be True.")

    crt_ca_file_name: str = Path(CA_CERT_FILE).stem + ".crt"
    crt_ca_file_path: str = str(Path(CA_CERT_FILE).parent) + os.sep + crt_ca_file_name
    crt_ca_shared_target_path: str = f"{CERTIFICATES_SHARE_DIRECTORY}/{crt_ca_file_name}"

    install_lines = ["#!/bin/bash\n"
                     "# If you want the proxy environment to be available right away in your script, execute it with any of the 'source' commands:\n"
                     "# source client_install.sh\n"
                     "# . client_install.sh\n"
                     "\n\n"]
    uninstall_lines = ["#!/bin/bash\n"]

    # === INSTALLATION SCRIPT LINES ====================================================================================

    install_lines += [
        f"""PROXY_IP={proxy_ip}
PROXY_PORT={proxy_port}
PROXY_URL="http://${{PROXY_IP}}:${{PROXY_PORT}}"
"""]

    # Set certificates for https if apt or http is enabled.
    if set_apt or set_http or set_docker_daemon or set_docker_build:
        # Copy client certificate and update trusted certificates.
        install_lines += [
            f"""

# ---- proxy CA cert import -----------------------------------------------
sudo cp {crt_ca_file_name} {crt_ca_shared_target_path}
sudo update-ca-certificates
sudo chmod 644 {crt_ca_shared_target_path}
"""]

    if set_http:
        install_lines += [
            f"""

# ---- HTTP/S shell env ----------------------------------------------------------
cat <<EOF | sudo tee /etc/profile.d/proxy.sh
export http_proxy=${{PROXY_URL}}
export https_proxy=${{PROXY_URL}}

# Python requests package.
export REQUESTS_CA_BUNDLE={crt_ca_shared_target_path}

# Node.js/npm
export NODE_EXTRA_CA_CERTS={crt_ca_shared_target_path}
export npm_config_cafile={crt_ca_shared_target_path}
export npm_config_strict_ssl=true
EOF

if ! grep -q 'source /etc/profile.d/proxy.sh' ~/.bashrc; then
    echo 'source /etc/profile.d/proxy.sh' >> ~/.bashrc
fi
source /etc/profile.d/proxy.sh


# ---- HTTP/S sudo: preserve proxy/CA env ----------------------------------------
sudo bash -c 'set -euo pipefail
F=/etc/sudoers.d/proxy_env
cat >"$F" <<'"'SUDOERS'"'
Defaults env_keep += "http_proxy https_proxy HTTP_PROXY HTTPS_PROXY REQUESTS_CA_BUNDLE NODE_EXTRA_CA_CERTS npm_config_cafile npm_config_strict_ssl"
SUDOERS
chown root:root "$F"
chmod 0440 "$F"
if visudo -cf "$F" >/dev/null 2>&1; then
  echo "Installed sudoers fragment: $F"
else
  echo "ERROR: sudoers fragment failed validation; removing." >&2
  rm -f "$F"
  exit 1
fi'
"""]

    if set_apt:
        install_lines += [
            """

# ---- host APT -----------------------------------------------------------
cat <<EOF | sudo tee /etc/apt/apt.conf.d/01proxy
Acquire::http::Proxy  "${PROXY_URL}";
Acquire::https::Proxy "${PROXY_URL}";
EOF
"""]

    if set_docker_build:
        install_lines += [
            """

# ---- Docker BuildKit ----------------------------------------------------
# This is needed in order to execute [docker build] commands. You don't need to restart docker daemon for this.

# This is for running docker with sudo
sudo mkdir -p /root/.docker            # system-wide, covers root-owned scripts
sudo tee /root/.docker/config.json >/dev/null <<EOF
{
  "proxies": {
    "default": {
      "httpProxy":  "${PROXY_URL}",
      "httpsProxy": "${PROXY_URL}",
      "noProxy":    "localhost,127.0.0.1,.mycorp.local"
    }
  }
}
EOF

# This is for running docker with regular user
mkdir -p ~/.docker            # system-wide, covers root-owned scripts
tee ~/.docker/config.json >/dev/null <<EOF
{
  "proxies": {
    "default": {
      "httpProxy":  "${PROXY_URL}",
      "httpsProxy": "${PROXY_URL}",
      "noProxy":    "localhost,127.0.0.1,.mycorp.local"
    }
  }
}
EOF
"""]

    if set_docker_daemon:
        install_lines += [
            """

# ---- Docker daemon ------------------------------------------------------
sudo mkdir -p /etc/systemd/system/docker.service.d
cat <<EOF | sudo tee /etc/systemd/system/docker.service.d/http-proxy.conf
[Service]
Environment="HTTP_PROXY=${PROXY_URL}/"
Environment="HTTPS_PROXY=${PROXY_URL}/"
EOF

if systemctl status docker.service >/dev/null 2>&1; then
    systemctl daemon-reload
    systemctl restart docker.service
fi
"""]

    if set_docker_build:
        install_lines += [
            f"""

# ---- Docker Build Wrapper ----------------------------------------------
# This create a docker build command wrapper that will inject the proxie's CA certificate into the image.
sudo mkdir -p /opt/docker-wrap
sudo tee   /opt/docker-wrap/docker >/dev/null <<'WRAP'
#!/usr/bin/env bash
# Lightweight wrapper that patches the Dockerfile *before* the real
# engine ever sees it, so every RUN step already trusts your proxy CA.

wrapdir="/opt/docker-wrap"

# --- find the first docker executable that isn't us -----------------
find_real_docker() {{
  local p IFS=:
  for p in $PATH; do
    [[ $p == "$wrapdir" ]] && continue          # skip the wrapper dir
    [[ -x "$p/docker" ]] && {{ echo "$p/docker"; return; }}
  done
  # fallback to the canonical location used by all Debian/Ubuntu/RHEL packages
  echo /usr/bin/docker
}}

real="$(find_real_docker)"

# -------------------------------------------------------------------
if [[ $1 == build ]]; then
  ctx="${{@: -1}}"; [[ $ctx == -* ]] && ctx="."
  tmp=$(mktemp -d)
  rsync -a --delete "$ctx"/ "$tmp"/
  cp {crt_ca_shared_target_path} "$tmp"/{crt_ca_file_name}

  cat >"$tmp"/.patch <<'PATCH'
COPY {crt_ca_file_name} {crt_ca_shared_target_path}
ENV  SSL_CERT_FILE={crt_ca_shared_target_path} \\
     REQUESTS_CA_BUNDLE={crt_ca_shared_target_path} \\
     CURL_CA_BUNDLE={crt_ca_shared_target_path}
RUN  /bin/sh -c 'set -e ; \\
        {{ command -v update-ca-certificates && update-ca-certificates ;}} || \\
        {{ command -v update-ca-trust      && update-ca-trust extract ;}} || true'
PATCH

  awk 'NR==FNR{{p=p $0 ORS;next}} /^FROM[[:space:]]/{{print;print p;next}}1' \\
      "$tmp"/.patch "$tmp"/Dockerfile >"$tmp"/Dockerfile.patched
  mv "$tmp"/Dockerfile.patched "$tmp"/Dockerfile
  rm "$tmp"/.patch

  set -- "${{@:1:$(($#-1))}}" "$tmp"
  "$real" "$@"; status=$?
  rm -rf "$tmp"; exit $status
fi

exec "$real" "$@"
WRAP
sudo chmod +x /opt/docker-wrap/docker

# Use this to use the wrapper script:
# (
#   export PATH="/opt/docker-wrap:$PATH"        # wrapper wins PATH lookup
#   ./test_build.sh                       # the bash file that includes the docker build command
# )
"""]

    # === EOF INSTALLATION SCRIPT LINES ================================================================================
    # === UNINSTALLATION SCRIPT LINES ==================================================================================
    # If we imported the proxy CA cert, remove it and refresh trust store.
    if set_apt or set_http or set_docker_daemon or set_docker_build:
        uninstall_lines += [
            f"""# ---- proxy CA cert removal ---------------------------------------------
sudo rm -f {crt_ca_shared_target_path}
if command -v update-ca-certificates >/dev/null 2>&1; then
    sudo update-ca-certificates
elif command -v update-ca-trust >/dev/null 2>&1; then
    sudo update-ca-trust extract
fi
"""]

    if set_http:
        uninstall_lines += [
            """# ---- HTTP/S shell env UNDO ------------------------------------------------------
# Remove global profile and bashrc sourcing; drop vars from current shell.
sudo rm -f /etc/profile.d/proxy.sh
sed -i '/source \\/etc\\/profile.d\\/proxy.sh/d' ~/.bashrc || true

unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY REQUESTS_CA_BUNDLE CURL_CA_BUNDLE SSL_CERT_FILE


# ---- HTTP/S sudo: remove proxy env preservation UNDO ----------------------------------------
sudo bash -c 'set -euo pipefail
F=/etc/sudoers.d/proxy_env
if [ ! -e "$F" ]; then
  echo "Nothing to remove: $F not found"
  exit 0
fi

# Disable first, then validate the whole config
mv "$F" "${F}.disabled"

if visudo -c >/dev/null 2>&1; then
  rm -f "${F}.disabled"
  echo "Removed sudoers fragment: $F"
else
  echo "ERROR: sudoers invalid after removal; restoring." >&2
  mv "${F}.disabled" "$F"
  exit 1
fi'
"""]

    if set_apt:
        uninstall_lines += [
            """# ---- host APT UNDO -------------------------------------------------------
# Remove apt proxy configuration.
sudo rm -f /etc/apt/apt.conf.d/01proxy
"""]

    if set_docker_build:
        uninstall_lines += [
            """# ---- Docker BuildKit UNDO -----------------------------------------------
# Remove the Docker CLI proxy configs created during install (root and user).
# Safe because install overwrote these files with proxy-only content.
sudo rm -f /root/.docker/config.json
sudo rmdir /root/.docker 2>/dev/null || true

rm -f ~/.docker/config.json
rmdir ~/.docker 2>/dev/null || true
"""]

    if set_docker_daemon:
        uninstall_lines += [
            """# ---- Docker daemon UNDO --------------------------------------------------
# Remove systemd drop-in and restart docker if it’s running.
sudo rm -f /etc/systemd/system/docker.service.d/http-proxy.conf
sudo rmdir /etc/systemd/system/docker.service.d 2>/dev/null || true

if systemctl status docker.service >/dev/null 2>&1; then
    sudo systemctl daemon-reload
    sudo systemctl restart docker.service
fi
"""]

    if set_docker_build:
        uninstall_lines += [
            """# ---- Docker Build Wrapper UNDO -------------------------------------------
sudo rm -f /opt/docker-wrap/docker
sudo rmdir /opt/docker-wrap 2>/dev/null || true
"""]

    # === EOF UNINSTALLATION SCRIPT LINES ===============================================================================

    # Write the installation script file.
    install_script = "".join(install_lines)
    client_install_file_path: str = os.path.join(CLIENT_INSTALLATION_FILES_DIRECTORY, CLIENT_INSTALL_FILE_NAME)
    with open(client_install_file_path, "w") as f:
        f.write(install_script)
    os.chmod(client_install_file_path, 0o755)

    # Write the uninstallation script file.
    uninstall_script = "".join(uninstall_lines)
    client_uninstall_file_path: str = os.path.join(CLIENT_INSTALLATION_FILES_DIRECTORY, CLIENT_UNINSTALL_FILE_NAME)
    with open(client_uninstall_file_path, "w") as f:
        f.write(uninstall_script)
    os.chmod(client_uninstall_file_path, 0o755)

    # Copy the CA certificate crt to the client files directory.
    shutil.copy(crt_ca_file_path, CLIENT_INSTALLATION_FILES_DIRECTORY)


def is_dummy_interface_available(
        availability_wait_seconds: int = 10
) -> bool:
    """
    Check if the dummy network interface is available after creation.
    :return: bool, True if the dummy interface is available, False otherwise.
    """

    def is_interface_available_for_listen(addr: str) -> bool:
        """
        Return True, if the given IPv4 address can be bound & listened on
        by this host (i.e., it's valid and assigned to a local interface).
        Otherwise, return False.

        Notes:
        - Uses TCP and an ephemeral port (0) so it won't collide with existing services.
        - This does NOT check reachability from other hosts; only local bind/listen ability.
        """
        # Validate it's an IPv4 dotted-quad
        try:
            ipaddress.IPv4Address(addr)
        except ipaddress.AddressValueError:
            return False

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                # Avoid TIME_WAIT weirdness across platforms
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                # Bind to an ephemeral port on the requested address
                s.bind((addr, 0))
                # Put it into listening state to be thorough
                s.listen(1)
                return True
        except OSError:
            return False


    count = 0
    while count < availability_wait_seconds:
        is_interface_created: bool = is_interface_available_for_listen(DummyInterfaceConfig.INTERFACE_IP)
        print(f"[+] Waiting for dummy interface creation... {count + 1}/5")
        if is_interface_created:
            print(f"[+] Interface available: {is_interface_created}")
            return True
        time.sleep(1)
        count += 1

    return False


def run_servers_main(
        ca_cert_file: str = ParserDefaults.CA_CERT_FILE,
        cache_dir: str = ParserDefaults.CACHE_DIR,
        certs_dir: str = ParserDefaults.CERTS_DIR,
        listen_ip: str = ParserDefaults.LISTEN_IP,
        listen_port: int = ParserDefaults.LISTEN_PORT,
        localhost: bool = ParserDefaults.LOCALHOST,
        client_files_dir: str = ParserDefaults.CLIENT_FILES_DIR,
        client_script_options: set = None,
        warm_apt_cache: bool = ParserDefaults.WARM_APT_CACHE,
        go_offline: bool = ParserDefaults.GO_OFFLINE
) -> int:
    """
    Run the main server for the MITM caching proxy.
    :param ca_cert_file:
    :param cache_dir:
    :param certs_dir:
    :param listen_ip:
    :param listen_port:
    :param localhost:
    :param client_files_dir:
    :param client_script_options:
    :param warm_apt_cache:
    :param go_offline:

    :return: int, 0 on success, 1 on error.
    """

    if client_script_options is None:
        client_script_options = set(CLIENT_SCRIPT_DEFAULT_FLAGS.keys())
    try:
        server_bind_ip, client_installation_script_ip = _get_listening_and_script_ips_by_settings(
            localhost=localhost,
            listen_ip=listen_ip,
            client_script_options=client_script_options
        )
    except (NoInterfacesFoundError, MoreThanOneInterfaceFoundError) as e:
        console.print(
            f"[+] ERROR: {e}\n"
            "    Please check your network interfaces and ensure there is a valid interface with an IP address.\n"
            "    OR Use [--localhost] option to bind to, OR use [--listen-ip] option to specify a valid IP address.",
            style="red", markup=False
        )
        return 1
    except InterfaceArgumentsError as e:
        console.print(f"[+] ERROR: {e}", style="red", markup=False)
        return 1


    if client_installation_script_ip == DummyInterfaceConfig.INTERFACE_IP:
        create_dummy_interface_lines = [
            f"""

# ---- Create dummy network interface -------------------------------------
sudo tee /etc/systemd/network/10-proxy.netdev >/dev/null <<'EOF'
[NetDev]
Name={DummyInterfaceConfig.NAME}
Kind=dummy
EOF

sudo tee /etc/systemd/network/20-proxy.network >/dev/null <<EOF
[Match]
Name={DummyInterfaceConfig.NAME}

[Network]
Address={DummyInterfaceConfig.INTERFACE_IP}/32
EOF

sudo systemctl daemon-reload
sudo systemctl restart systemd-networkd
"""]

        # Build the script (strict mode makes the shell exit on the first error)
        script = "set -Eeuo pipefail\n" + textwrap.dedent("\n".join(create_dummy_interface_lines)).strip() + "\n"

        try:
            completed = subprocess.run(
                ["bash", "-s"],  # read script from stdin
                input=script,  # the script itself (in-memory)
                text=True,
                capture_output=True,  # capture for error reporting
                check=True   # raise on non-zero exit
            )
            # Optional: print outputs on success
            if completed.stdout:
                print(completed.stdout, end="")
            if completed.stderr:
                print(completed.stderr, end="", file=sys.stderr)

        except subprocess.CalledProcessError as e:
            raise RuntimeError(
                f"Dummy interface creation failed (exit code {e.returncode}).\n"
                f"--- STDOUT ---\n{e.stdout or ''}\n"
                f"--- STDERR ---\n{e.stderr or ''}"
            ) from e

        global DUMMY_INTERFACE_CREATED
        DUMMY_INTERFACE_CREATED = True

        is_dummy_interface_available(DummyInterfaceConfig.AVAILABILITY_WAIT_SECONDS)


    if cache_dir is None:
        cache_dir = CACHE_DIRECTORY
    if certs_dir is None:
        certs_dir = CERTS_DIRECTORY

    update_global_variables(cache_dir, certs_dir, ca_cert_file, client_files_dir)


    os.makedirs(CACHE_DIRECTORY, exist_ok=True)
    os.makedirs(CERTS_DIRECTORY, exist_ok=True)
    os.makedirs(LOGS_DIRECTORY, exist_ok=True)
    os.makedirs(CLIENT_INSTALLATION_FILES_DIRECTORY, exist_ok=True)

    os.makedirs(CERTS_SERVER_DIRECTORY, exist_ok=True)
    os.makedirs(CERTS_CA_DIRECTORY, exist_ok=True)

    # Creating certificates for the cache server.
    if not os.path.exists(CA_CERT_FILE):
        create_ca_certificates()
    create_crt_and_der_from_pem()


    installation_scripts_kwargs: dict = _set_installation_scripts_kwargs(client_script_options)
    create_client_installation_files(proxy_ip=client_installation_script_ip, proxy_port=listen_port, **installation_scripts_kwargs)

    threading.Thread(
        target=run_proxy_server,
        kwargs=dict(listen_ip=server_bind_ip, listen_port=listen_port),
        daemon=True
    ).start()

    if warm_apt_cache:
        run_full_apt_update(proxy_ip=server_bind_ip, proxy_port=listen_port)

    if go_offline:
        global GO_OFFLINE
        GO_OFFLINE = True

        console.print("[+] Going offline after initial setup and optional APT cache warming.", style="yellow")
        subprocess.check_call(shlex.split("sudo ip route add blackhole default"))

    if 'b' in client_script_options:
        console.print("[+] To use the Docker BuildKit proxy wrapper, use this around your docker build commands (bash):", style="yellow", markup=False)
        console.print("==============================================")
        console.print("(")
        console.print("  export PATH=\"/opt/docker-wrap:$PATH\"        # wrapper wins PATH lookup", style="yellow")
        console.print("  ./test_build.sh                       # the bash file that includes the docker build command", style="yellow")
        console.print(")")
        console.print("==============================================")

    console.print(f"[+] Proxy server is listening on: {server_bind_ip}:{listen_port}", markup=False)

    while True:
        time.sleep(1)


def _get_listening_and_script_ips_by_settings(
        localhost: bool,
        listen_ip: str,
        client_script_options: set
) -> tuple[str, str]:

    if listen_ip and listen_ip != '0.0.0.0' and localhost:
        raise InterfaceArgumentsError("[+] ERROR: No need to set [--localhost] if you are explicitly setting [--listen-ip]. You can do this only if [--listen-ip] is '0.0.0.0'")

    note_message: str = (
        "and if there is a 'b' in [--client-script-options] (by default there is); "
        "This means that Docker BuildKit proxy will be set to a loopback address that is not reachable from inside the container in the time of building. "
        f"So, we're creating a dummy network interface with IP address {DummyInterfaceConfig.INTERFACE_IP} and setting the Docker BuildKit proxy to this address "
        "and all the other client proxies in the client installation scripts (instead of '127.x.x.x'). "
        "Finally, the listening IP for the proxy server will be set to this address as well."
    )

    if listen_ip and listen_ip.startswith('127.') and 'b' in client_script_options:
        console.print(f"[+] NOTE: If you are using [--listen-ip] that starts with '127.' (loopback address), {note_message}",
                      style="yellow", markup=False)

    if localhost and 'b' in client_script_options:
        console.print(
            f"[+] NOTE: If you are using [--localhost] the proxy listening will be assigned to '127.0.0.1', {note_message}",
            style="yellow", markup=False)


    if not listen_ip and localhost:
        return DummyInterfaceConfig.INTERFACE_IP, DummyInterfaceConfig.INTERFACE_IP
    elif not listen_ip and not localhost:
        ip_address: str = find_interface_ip()
        return ip_address, ip_address
    elif listen_ip and listen_ip == '0.0.0.0' and localhost:
        return listen_ip, DummyInterfaceConfig.INTERFACE_IP
    elif listen_ip and listen_ip == '0.0.0.0' and not localhost:
        return listen_ip, find_interface_ip()
    elif listen_ip and listen_ip != '0.0.0.0':
        return listen_ip, listen_ip
    else:
        raise InterfaceArgumentsError("[+] ERROR: Invalid combination of [--localhost] and [--listen-ip] arguments.")


def find_interface_ip() -> str:
    """
    Try to find an interface IP address that is not a loopback address and not docker interface.
    If there are more than 2 network interfaces, error will be returned.

    :return: string, the interface IP address.
    """

    ip_address: str | None = None

    # First try to get the IP address of the default interface that is used for outbound connections.
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Connect to an unreachable address; the IP used for this connection will be our outbound IP.
        s.connect(('10.255.255.255', 1))
        ip_address = s.getsockname()[0]
    except Exception as e:
        _ = e
        pass
    finally:
        s.close()

    # If the IP address was found return it.
    if ip_address:
        return ip_address

    # If the IP address wasn't found it could mean that there is no internet connection, but the interface can exist
    # and other offline hosts can connect to it.
    # So we will try to find it.
    interfaces: list[dict[str, str]] = physical_ipv4()
    if len(interfaces) == 0:
        raise NoInterfacesFoundError
    if len(interfaces) > 1:
        raise MoreThanOneInterfaceFoundError

    return interfaces[0]['ipv4']


def physical_ipv4(include_down: bool = True) -> list[dict]:
    """
    Get a list of physical network interfaces with their IPv4 addresses and prefix lengths.

    :param include_down: bool, if True, include down interfaces; if False, only include up interfaces.
    :return: list of dicts, each dict contains:
        - "iface": interface name (str)
        - "ipv4": IPv4 address (str)
        - "prefix": prefix length (int)
    """

    def is_physical_linux(internal_ifname: str) -> bool:
        """
        Check if the interface is a physical interface on Linux.

        :param internal_ifname: str, interface name.
        :return: bool, True if the interface is physical, False otherwise.

        1. Exclude loopback interface "lo".
        2. Check if the interface is a real device by checking its path in /sys/class/net.
        3. Exclude virtual devices by checking if the path contains "/devices/virtual/".
        4. Return True if the interface is physical, False otherwise.
        """
        if internal_ifname == "lo":
            return False
        real = os.path.realpath(f"/sys/class/net/{internal_ifname}")
        return "/devices/virtual/" not in real

    def ipv4_prefixlen(netmask: str) -> int:
        return ipaddress.IPv4Network(f"0.0.0.0/{netmask}", strict=False).prefixlen

    stats = psutil.net_if_stats()
    interface_list: list = []
    for ifname, addrs in psutil.net_if_addrs().items():
        if not is_physical_linux(ifname):
            continue
        if not include_down and not stats.get(ifname, None) or not stats[ifname].isup:
            continue
        for a in addrs:
            if a.family == socket.AF_INET:
                prefix = ipv4_prefixlen(a.netmask) if a.netmask else 32
                interface_list.append({
                    "iface": ifname,
                    "ipv4": a.address,
                    "prefix": prefix
                })

    return interface_list


def _set_installation_scripts_kwargs(
        client_script_options: set
) -> dict:
    """
    Set the keyword arguments for the client installation scripts based on the provided options.

    :param client_script_options: set of letters representing the options to set in the client installation scripts.
    :return: dict with keyword arguments for creating client installation files.
    """

    result_dict: dict = {}
    for string_key, character in CLIENT_INSTALLATION_SCRIPT_DICT.items():
        result_dict[string_key] = character in client_script_options

    return result_dict


def _make_arg_parser():
    def char_flags(s: str):
        s = s.lower()
        allowed = set(CLIENT_SCRIPT_DEFAULT_FLAGS.keys())
        if not s:
            raise argparse.ArgumentTypeError("Provide at least one option letter.")
        bad = [ch for ch in s if ch not in allowed]
        if bad:
            raise argparse.ArgumentTypeError(
                f"Invalid letters: {''.join(bad)}. Allowed: {''.join(sorted(allowed))}"
            )
        return set(s)  # unique letters, order not important

    parser = argparse.ArgumentParser(
        description=(
            "MITM Caching Proxy Server\n"
            "\n"
            "Client installation scripts notice:\n"
            "1. You can edit the generated client installation scripts to suit your needs.\n"
            "2. If you install docker proxy configuration file before the docker is installed on the client, they will be applied right away, so you don't need to reapply them after installing Docker.\n"
            "\n"
            "General Notices:\n"
            "APT Cache. If you want to use the APT cache you need to warm up the cache with full APT data by running these commands on the client after proxy setup:\n"
            "sudo rm -rf /var/lib/apt/lists/*               # Delete current apt indexes.\n"
            "sudo apt update -o Acquire::PDiffs=false       # Download the full indexes.\n"
            "OR you can run this script with [--warm-apt-cache] option to warm up the cache automatically.\n"
            "\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        '--ca-cert-file', type=str, default=ParserDefaults.CA_CERT_FILE,
        help="Full path to CA certificate file that will contain the private key. "
             "Default: <working directory>/certs/server_ca/cache_ca.pem. If non-existent it will be created.")
    parser.add_argument(
        '--cache-dir', type=str, default=ParserDefaults.CACHE_DIR,
        help="Full path to cache directory. Default: <working directory>/cache")
    parser.add_argument(
        '--certs-dir', type=str, default=ParserDefaults.CERTS_DIR,
        help="Full path to certificates directory. Default: <working directory>/certs")
    parser.add_argument(
        "-li", "--listen-ip", type=str, default=ParserDefaults.LISTEN_IP,
        help="Proxy server Interface/IP to bind explicitly. \n"
             "If you use [0.0.0.0] as [--listen-ip], you can set [--local] to use '127.0.0.1' in the client proxy installation scripts, "
             "without using [--local] the client installation scripts will be set to the default host's network interface IP address.\n"
             "If you set [0.0.0.0] as [--listen-ip] and 'b' in [--client-script-options], (which is the default), and [--local] is provided, "
             f"then a dummy interface with IP address {DummyInterfaceConfig.INTERFACE_IP} will be created and used to set all the proxies in the client installation scripts.\n"
             f"This is because Docker BuildKit will not be able to connect to '127.x.x.x' from inside the container while building an image.\n")
    parser.add_argument(
        '-lp', '--listen-port', type=int, default=ParserDefaults.LISTEN_PORT,
        help=f"Server cache port. Default: {str(ParserDefaults.LISTEN_PORT)}")
    parser.add_argument(
        '-local', '--localhost', action='store_true',
        help="If set, the server will bind to localhost (127.0.0.1) instead of the network interface and this IP address will be configured in client installation scripts.\n"
             "If not set, the server will try to find your network interface IP address and use it for server bind/listen and in the client installation scripts.\n")
    parser.add_argument(
        '-cfd', '--client-files-dir', type=str, default=ParserDefaults.CLIENT_FILES_DIR,
        help="Full path to directory where ubuntu client installation bash scripts and required files will be stored. Default: <working directory>/client_files")
    parser.add_argument(
        '-cso', '--client-script-options', metavar='LETTERS', type=char_flags, default=ParserDefaults.CLIENT_SCRIPT_OPTIONS,
        help="Options:\n"
             "" + "\n".join(f"{k}={v}" for k, v in CLIENT_SCRIPT_DEFAULT_FLAGS.items()) +
             "\n\n"
             "Example: -cso ahp\n"
             "This will set the HTTP/HTTPS proxy environment variables, APT proxy configuration, and "
             "Python requests module CA bundle.\n"
             "Docker daemon and Docker BuildKit proxies will not be set.\n"
    )
    parser.add_argument(
        '-wa', '--warm-apt-cache', action='store_true',
        help="If set, the APT cache will be warmed up with full APT data by running the commands:\n"
             "sudo rm -rf /var/lib/apt/lists/*               # Delete current apt indexes.\n"
             "sudo apt update -o Acquire::PDiffs=false       # Download the full indexes.\n"
             "Also, temporary proxy setting for APT will be set to the proxy server IP address and port, while executing the update.\n"
             "This is useful if you want to use the APT cache and have it ready for use right after the proxy setup.\n"
             "If not set, you will need to run these commands manually after the proxy setup.\n"
    )
    parser.add_argument(
        '-go', '--go-offline', action='store_true',
        help="If set, the command will be executed:\n"
             "[sudo ip route add blackhole default]\n"
             "Which will disable the internet access on the host machine (go offline).\n"
             "When you press [Ctrl]+[C], to exit proxy script, it will be removed.\n"
             "You can run at any time:\n"
             "[sudo ip route del blackhole default]\n"
             "To restore the internet access on the host machine.\n"
             "You can use it to test if your warmed cache is working properly in offline environment on the localhost.\n"
    )

    return parser


if __name__ == '__main__':
    arg_parser = _make_arg_parser()
    exec_args = arg_parser.parse_args()

    try:
        exit_result: int = run_servers_main(**vars(exec_args))
    except KeyboardInterrupt:
        print("Exiting...")
        remove_dummy_interface()
        exit_result = 0

    sys.exit(exit_result)
