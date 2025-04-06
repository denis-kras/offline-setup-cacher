#!/usr/bin/env python3
import os
import ssl
import subprocess
import sys
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
import shlex
import shutil
import socket
import time

# noinspection PyPackageRequirements
from cryptography import x509
# noinspection PyPackageRequirements
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
# noinspection PyPackageRequirements
from cryptography.hazmat.primitives import hashes, serialization
# noinspection PyPackageRequirements
from cryptography.hazmat.primitives.asymmetric import rsa
# noinspection PyPackageRequirements
from cryptography.hazmat.primitives.serialization import load_pem_private_key


CACHE_SERVER_PROXY_PORT: int = 3129
DOCKER_CACHE_REGISTRY_PORT: int = 3128

SCRIPT_DIRECTORY: str = os.path.dirname(os.path.realpath(__file__))
CACHE_DIRECTORY: str = str(Path(SCRIPT_DIRECTORY, 'cache'))
CERTS_DIRECTORY: str = str(Path(SCRIPT_DIRECTORY, 'certs'))
CLIENT_INSTALLATION_FILES_DIRECTORY: str = str(Path(SCRIPT_DIRECTORY, 'client_files'))

CACHE_SERVER_DIRECTORY: str = 'server'
CACHE_DOCKER_DIRECTORY: str = 'docker'

CERTS_SERVER_DIRECTORY: str = 'server_certs'
CERTS_CA_DIRECTORY: str = 'server_ca'
CERTS_DOCKER_DIRECTORY: str = 'docker'

CA_CERT_FILE: str = str(Path(CERTS_CA_DIRECTORY, 'cache_ca.pem'))
CA_COMMON_NAME: str = "Proxy Server CA"

LOGS_DIRECTORY: str = str(Path(SCRIPT_DIRECTORY, 'logs'))

REQUESTS_CSV_PATH: str = str(Path(LOGS_DIRECTORY, 'requests_log.csv'))
CACHED_CSV_PATH: str = str(Path(LOGS_DIRECTORY, 'unique_cached_files.csv'))
REQUESTS_RESPONSES_LOG_PATH: str = str(Path(LOGS_DIRECTORY, 'full_requests_responses.log'))

DOCKER_CONTAINER_NAME: str = "registry_proxy"
DOCKER_PROXY_IMAGE_NAME: str = "rpardini/docker-registry-proxy:0.6.5"

log_lock = threading.Lock()
logged_cached = set()

ENABLE_FULL_LOG: bool = True
FULL_LOG_REQUEST_RESPONSE_TRUNCATION_LIMIT: int = 300

DOCKER_READY_EVENT = threading.Event()


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
    global CACHE_SERVER_DIRECTORY
    global CACHE_DOCKER_DIRECTORY
    global CERTS_SERVER_DIRECTORY
    global CERTS_CA_DIRECTORY
    global CERTS_DOCKER_DIRECTORY
    global CA_CERT_FILE

    CACHE_DIRECTORY = cache_dir
    CERTS_DIRECTORY = certs_dir
    CACHE_SERVER_DIRECTORY = str(Path(CACHE_DIRECTORY, CACHE_SERVER_DIRECTORY))
    CACHE_DOCKER_DIRECTORY = str(Path(CACHE_DIRECTORY, CACHE_DOCKER_DIRECTORY))
    CERTS_SERVER_DIRECTORY = str(Path(CERTS_DIRECTORY, CERTS_SERVER_DIRECTORY))
    CERTS_CA_DIRECTORY = str(Path(CERTS_DIRECTORY, CERTS_CA_DIRECTORY))
    CERTS_DOCKER_DIRECTORY = str(Path(CERTS_DIRECTORY, CERTS_DOCKER_DIRECTORY))

    if not ca_cert_file:
        CA_CERT_FILE = str(Path(CERTS_DIRECTORY, CA_CERT_FILE))
    else:
        CA_CERT_FILE = ca_cert_file

    if client_files_dir:
        CLIENT_INSTALLATION_FILES_DIRECTORY = client_files_dir


def create_ca_certificates():
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

    print("CA Certificates generated.")


def is_admin() -> bool:
    """
    Function checks on Windows or POSIX OSes if the script is executed under Administrative Privileges.
    :return: True / False.
    """

    if os.name == 'nt':
        import ctypes
        if ctypes.windll.shell32.IsUserAnAdmin() == 0:
            result = False
        else:
            result = True
    else:
        if 'SUDO_USER' in os.environ and os.geteuid() == 0:
            result = True
        else:
            result = False

    return result


def is_docker_installed() -> bool:
    try:
        # Run the command "docker --version"
        result = subprocess.run(
            ["docker", "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if result.returncode == 0:
            return True
        else:
            return False
    except FileNotFoundError:
        return False


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


def generate_cache_key(url):
    """Generate SHA-256 hash as the cache key.
       For docker registry manifest endpoints, ignore query parameters.
    """
    parsed = urlparse(url)
    if parsed.netloc.endswith("docker.io") and "/manifests/" in parsed.path:
        normalized = parsed.netloc + parsed.path
    else:
        normalized = parsed.netloc + parsed.path + ("?" + parsed.query if parsed.query else "")
    return hashlib.sha256(normalized.encode('utf-8')).hexdigest()


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


class MitmHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    # noinspection PyPep8Naming
    def do_GET(self):
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

        if parsed.scheme in ["http", "https"]:
            full_url = parsed.netloc + parsed.path + ("?" + parsed.query if parsed.query else "")
        else:
            full_url = self.headers.get("Host", "unknown_host") + self.path

        safe_key = generate_cache_key(full_url)
        cache_file = os.path.join(CACHE_SERVER_DIRECTORY, safe_key)
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        source_ip = self.client_address[0]
        method = "GET"

        # Prepare full request log text.
        req_text = f"{self.requestline}\n{self.headers}"

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
            append_cached_log(full_url, safe_key, file_hash)
            append_request_log(timestamp, source_ip, method, full_url, target_port, cached_response['status'], safe_key, file_hash)
            resp_text = (f"Status: {cached_response['status']} {cached_response['reason']}\n"
                         f"Headers: {cached_response['headers']}\n"
                         f"Body (first {str(FULL_LOG_REQUEST_RESPONSE_TRUNCATION_LIMIT)} bytes): "
                         f"{cached_response['body'][:FULL_LOG_REQUEST_RESPONSE_TRUNCATION_LIMIT]!r} (total {len(cached_response['body'])} bytes)")
                         # f"Body: {cached_response['body']!r}")
            if ENABLE_FULL_LOG:
                log_full_pair(req_text, resp_text)
            print(f"Served cached GET response from {cache_file}")
            return

        try:
            conn.request("GET", parsed.path + ("?" + parsed.query if parsed.query else ""), headers=self.headers)
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
            append_cached_log(full_url, safe_key, file_hash)
            append_request_log(timestamp, source_ip, method, full_url, target_port, remote_response.status, safe_key, file_hash)
            resp_text = (f"Status: {remote_response.status} {remote_response.reason}\n"
                         f"Headers: {remote_response.getheaders()}\n"
                         f"Body (first {str(FULL_LOG_REQUEST_RESPONSE_TRUNCATION_LIMIT)} bytes): "
                         f"{body[:FULL_LOG_REQUEST_RESPONSE_TRUNCATION_LIMIT]!r} (total {len(body)} bytes)")
                         # f"Body: {body!r}")
            if ENABLE_FULL_LOG:
                log_full_pair(req_text, resp_text)
            print(f"Fetched and cached new GET response to {cache_file}")
        except Exception as e:
            if "auth.docker.io/token" in full_url and os.path.exists(cache_file):
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
                append_request_log(timestamp, source_ip, method, full_url, target_port, cached_response['status'], safe_key, file_hash)
                resp_text = (f"Status: {cached_response['status']} {cached_response['reason']}\n"
                             f"Headers: {cached_response['headers']}\n"
                             f"Body (first {str(FULL_LOG_REQUEST_RESPONSE_TRUNCATION_LIMIT)} bytes): "
                             f"{cached_response['body'][:FULL_LOG_REQUEST_RESPONSE_TRUNCATION_LIMIT]!r} (total {len(cached_response['body'])} bytes)")
                             # f"Body: {cached_response['body']!r}")
                if ENABLE_FULL_LOG:
                    log_full_pair(req_text, resp_text)
                print(f"Network error for token; served cached GET response from {cache_file}")
            else:
                self.send_error(502, f"Error fetching remote server: {e}")
                append_request_log(timestamp, source_ip, method, full_url, target_port, "", "", "")

    # noinspection PyPep8Naming
    def do_HEAD(self):
        parsed = urlparse(self.path)
        if parsed.scheme in ["http", "https"]:
            full_url = parsed.netloc + parsed.path + ("?" + parsed.query if parsed.query else "")
        else:
            full_url = self.headers.get("Host", "unknown_host") + self.path
        safe_key = generate_cache_key(full_url)
        cache_file = os.path.join(CACHE_SERVER_DIRECTORY, safe_key)

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
            conn.close()
            resp_text = (f"Status: {remote_response.status} {remote_response.reason}\n"
                         f"Headers: {remote_response.getheaders()}")
            if ENABLE_FULL_LOG:
                log_full_pair(req_text, resp_text)
        except Exception as e:
            self.send_error(502, f"Error fetching remote server: {e}")

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
        self.handle_one_request()

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
            cache_file = os.path.join(CACHE_SERVER_DIRECTORY, safe_key)
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

    # noinspection PyShadowingBuiltins
    def log_message(self, format, *args):
        print("%s - - [%s] %s" %
              (self.client_address[0],
               self.log_date_time_string(),
               format % args))

class ThreadedTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


def run_proxy_server(server_cache_port: int):
    """
    Run the main HTTP/HTTPS proxy server on the specified port.

    :param server_cache_port: integer, Port for the proxy server.
    """
    # noinspection PyTypeChecker
    server = ThreadedTCPServer(("", server_cache_port), MitmHTTPRequestHandler)
    print(f"MITM caching proxy server running on port {server_cache_port}")
    server.serve_forever()


def run_docker_cache_server(
        docker_cache_port: int,
        docker_cache_dir: str,
        docker_certs_dir: str
):
    """
    Run the custom docker registry that caches images and the manifest files of them.

    :param docker_cache_port: integer, docker cache listening port, 3128 is recommended, since it works out of the box.
    :param docker_cache_dir: string, full directory path that the cache will use to store files.
    :param docker_certs_dir: string, full directory path that the cache will use to store the ca certificate.
    :return:
    """

    def thread_worker():
        # Check if the container exists and remove it if it does.
        check_cmd = f"sudo docker ps -aq -f name={DOCKER_CONTAINER_NAME}"
        result = subprocess.run(shlex.split(check_cmd), capture_output=True, text=True)

        if result.stdout.strip():
            remove_cmd = f"sudo docker rm -f {DOCKER_CONTAINER_NAME}"
            subprocess.run(shlex.split(remove_cmd))
            print(f"Removed existing container: {DOCKER_CONTAINER_NAME}")

        cmd: str = (f'sudo docker run '
                    f'--rm '
                    f'--name {DOCKER_CONTAINER_NAME} '
                    # f'-it '
                    f'-p 0.0.0.0:{str(docker_cache_port)}:{str(docker_cache_port)} '
                    f'-e ENABLE_MANIFEST_CACHE=true '
                    f'-v "{docker_cache_dir}":/docker_mirror_cache '
                    f'-v "{docker_certs_dir}":/ca '
                    f'{DOCKER_PROXY_IMAGE_NAME}')

        cmd_list: list = shlex.split(cmd)
        print(f"Running docker cache server with command: {cmd}")
        # subprocess.run(cmd_list)
        process = subprocess.Popen(cmd_list,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE,
                                   text=True)

        # continuously read output to avoid mixed buffering:
        for line in process.stdout:
            print(line.rstrip(), flush=True)
            if "Starting nginx! Have a nice day" in line:
                DOCKER_READY_EVENT.set()

    threading.Thread(target=thread_worker, daemon=True).start()


def install_docker():
    # Update package lists
    subprocess.run(["sudo", "apt", "update"], check=True)

    # Install curl
    subprocess.run(["sudo", "apt", "install", "-y", "curl"], check=True)

    # Inform the user about Docker installation
    print("Installing Docker...")

    # Execute the Docker installation script via curl and sh
    subprocess.run("curl -fsSL https://get.docker.com | sh", shell=True, check=True)


def get_server_ip():
    """
    Determine the server's IP address (non-loopback).
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Connect to an unreachable address; the IP used for this connection will be our outbound IP.
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
    except Exception as e:
        _ = e
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip


def create_client_installation_files(
        disable_cache_server: bool,
        disable_docker_cache: bool,
):
    server_ip = get_server_ip()
    crt_ca_file_name: str = Path(CA_CERT_FILE).stem + ".crt"
    crt_ca_file_path: str = str(Path(CA_CERT_FILE).parent) + os.sep + crt_ca_file_name

    install_lines = ["#!/bin/bash\n"
                     "# If you want the proxy environment to be available right away in your script, execute it with any of the 'source' commands:\n"
                     "# source ./client_install.sh\n"
                     "# . ./client_install.sh\n"]
    uninstall_lines = ["#!/bin/bash\n"]

    # If the cache server is disabled, we simply note it.
    if not disable_cache_server:
        # -- Caching configuration --
        # 1. Retrieve and install the proxy's CA certificate.
        install_lines.append(
            f"sudo wget http://{server_ip}:{DOCKER_CACHE_REGISTRY_PORT}/ca.crt -O /usr/local/share/ca-certificates/docker_registry_proxy.crt\n")
        install_lines.append("\n")
        # 2. Copy client certificate and update trusted certificates.
        install_lines.append(f"sudo cp {crt_ca_file_name} /usr/local/share/ca-certificates/{crt_ca_file_name}\n")
        install_lines.append("sudo update-ca-certificates\n")
        install_lines.append("\n")
        install_lines.append("sudo chmod 644 /usr/local/share/ca-certificates/cache_ca.crt")
        install_lines.append("\n")
        # 3. Set permanent proxy environment variables.
        # Here we create a file in /etc/profile.d to set the proxy for all users on login.
        install_lines.append(f"echo 'export http_proxy=http://{server_ip}:{CACHE_SERVER_PROXY_PORT}' | sudo tee /etc/profile.d/proxy.sh\n")
        install_lines.append(
            f"echo 'export https_proxy=http://{server_ip}:{CACHE_SERVER_PROXY_PORT}' | sudo tee -a /etc/profile.d/proxy.sh\n")
        # Optionally, also set REQUESTS_CA_BUNDLE permanently.
        install_lines.append(
            f"echo 'export REQUESTS_CA_BUNDLE=/usr/local/share/ca-certificates/{crt_ca_file_name}' | sudo tee -a /etc/profile.d/proxy.sh\n")
        install_lines.append("\n")
        # Append source command to user's .bashrc if not already present
        install_lines.append("if ! grep -q 'source /etc/profile.d/proxy.sh' ~/.bashrc; then\n")
        install_lines.append("    echo 'source /etc/profile.d/proxy.sh' >> ~/.bashrc\n")
        install_lines.append("fi\n")
        # Source the proxy file to apply the settings to the current session
        install_lines.append("source /etc/profile.d/proxy.sh\n")
        install_lines.append("\n")
        # 4. Create APT proxy configuration.
        apt_conf = f"""Acquire::http::Proxy "http://{server_ip}:{CACHE_SERVER_PROXY_PORT}";
    Acquire::https::Proxy "http://{server_ip}:{CACHE_SERVER_PROXY_PORT}";"""
        install_lines.append("APT_CONF_BLOCK=$(cat <<'EOF'\n")
        install_lines.append(apt_conf + "\n")
        install_lines.append("EOF\n)\n")
        install_lines.append('echo "$APT_CONF_BLOCK" | sudo tee /etc/apt/apt.conf.d/01proxy\n')
        install_lines.append("\n")

        # Uninstallation for caching settings:
        uninstall_lines.append("sudo rm -f /usr/local/share/ca-certificates/docker_registry_proxy.crt\n")
        uninstall_lines.append(f"sudo rm -f /usr/local/share/ca-certificates/{crt_ca_file_name}\n")
        uninstall_lines.append("sudo rm -f /etc/apt/apt.conf.d/01proxy\n")
        uninstall_lines.append("sudo rm -f /etc/profile.d/proxy.sh\n")
        # Remove the sourcing command from the user's .bashrc if it exists
        uninstall_lines.append("sed -i '/source \\/etc\\/profile.d\\/proxy.sh/d' ~/.bashrc\n")
        uninstall_lines.append("sudo update-ca-certificates\n")

        # -- Docker configuration (only if not disabled) --
        if not disable_docker_cache:
            install_lines.append("\n# Docker proxy configuration\n")
            install_lines.append("sudo mkdir -p /etc/systemd/system/docker.service.d\n")
            install_lines.append("\n")
            docker_conf = f"""[Service]
    Environment="HTTP_PROXY=http://{server_ip}:{DOCKER_CACHE_REGISTRY_PORT}/"
    Environment="HTTPS_PROXY=http://{server_ip}:{DOCKER_CACHE_REGISTRY_PORT}/\""""
            install_lines.append("DOCKER_CONF_BLOCK=$(cat <<'EOF'\n")
            install_lines.append(docker_conf + "\n")
            install_lines.append("EOF\n)\n")
            install_lines.append(
                'echo "$DOCKER_CONF_BLOCK" | sudo tee /etc/systemd/system/docker.service.d/http-proxy.conf\n')
            install_lines.append("\n")
            # Only reload/restart docker if the service exists.
            install_lines.append("if systemctl status docker.service >/dev/null 2>&1; then\n")
            install_lines.append("    systemctl daemon-reload\n")
            install_lines.append("    systemctl restart docker.service\n")
            install_lines.append("fi\n")

            # Uninstallation for docker settings.
            uninstall_lines.append("\n# Remove Docker proxy configuration\n")
            uninstall_lines.append("sudo rm -f /etc/systemd/system/docker.service.d/http-proxy.conf\n")
            uninstall_lines.append("if systemctl status docker.service >/dev/null 2>&1; then\n")
            uninstall_lines.append("    systemctl daemon-reload\n")
            uninstall_lines.append("    systemctl restart docker.service\n")
            uninstall_lines.append("fi\n")
        else:
            uninstall_lines.append("# Docker proxy settings were not applied.\n")

    # Write the installation script file.
    install_script = "".join(install_lines)
    client_install_file_path: str = os.path.join(CLIENT_INSTALLATION_FILES_DIRECTORY, "client_install.sh")
    with open(client_install_file_path, "w") as f:
        f.write(install_script)
    os.chmod(client_install_file_path, 0o755)

    # Write the uninstallation script file.
    uninstall_script = "".join(uninstall_lines)
    client_uninstall_file_path: str = os.path.join(CLIENT_INSTALLATION_FILES_DIRECTORY, "client_uninstall.sh")
    with open(client_uninstall_file_path, "w") as f:
        f.write(uninstall_script)
    os.chmod(client_uninstall_file_path, 0o755)

    # Copy the CA certificate crt to the client files directory.
    print(crt_ca_file_path)
    print(CLIENT_INSTALLATION_FILES_DIRECTORY)
    shutil.copy(crt_ca_file_path, CLIENT_INSTALLATION_FILES_DIRECTORY)


def run_servers_main(
        disable_cache_server: bool,
        disable_docker_cache: bool,
        ca_cert_file: str,
        cache_dir: str,
        certs_dir: str,
        server_cache_port: int,
        docker_cache_port: int,
        install_prerequisites: bool,
        client_files_dir: str
):

    if not is_admin():
        print("This script must be run with sudo.")
        return 1

    if disable_cache_server and disable_docker_cache:
        print("Both cache server and docker cache are disabled. Exiting...")
        return 1

    if not disable_docker_cache and not is_docker_installed() and not install_prerequisites:
            print("Docker is not installed. Please install Docker to use the docker cache feature.\n"
                  "Run this script with the [--install_prerequisites] option to install Docker.")
            return 1

    os.makedirs(CACHE_DIRECTORY, exist_ok=True)
    os.makedirs(CERTS_DIRECTORY, exist_ok=True)
    os.makedirs(LOGS_DIRECTORY, exist_ok=True)
    os.makedirs(CLIENT_INSTALLATION_FILES_DIRECTORY, exist_ok=True)

    update_global_variables(cache_dir, certs_dir, ca_cert_file, client_files_dir)

    # Installing prerequisites if requested.
    if install_prerequisites:
        if not disable_docker_cache:
            install_docker()

    # Creating certificates for the cache server.
    if not disable_cache_server:
        os.makedirs(CACHE_SERVER_DIRECTORY, exist_ok=True)
        os.makedirs(CERTS_SERVER_DIRECTORY, exist_ok=True)
        os.makedirs(CERTS_CA_DIRECTORY, exist_ok=True)

        if not os.path.exists(CA_CERT_FILE):
            create_ca_certificates()

        create_crt_and_der_from_pem()

    create_client_installation_files(disable_cache_server, disable_docker_cache)

    # Executing the servers.
    if not disable_docker_cache:
        os.makedirs(CACHE_DOCKER_DIRECTORY, exist_ok=True)
        os.makedirs(CERTS_DOCKER_DIRECTORY, exist_ok=True)
        run_docker_cache_server(docker_cache_port, CACHE_DOCKER_DIRECTORY, CERTS_DOCKER_DIRECTORY)

        # Wait until the docker proxy server signals it's ready (with a timeout if needed)
        if DOCKER_READY_EVENT.wait(timeout=30):
            print(f"Docker caching proxy server running on port {docker_cache_port}")
        else:
            print("Docker caching proxy server did not start in time.")
            return 1

    if not disable_cache_server:
        run_proxy_server(server_cache_port)

    while True:
        time.sleep(1)

def parse_args():
    import argparse  # Ensure argparse is imported

    parser = argparse.ArgumentParser(description="MITM Caching Proxy Server")
    parser.add_argument('-dcs', '--disable_cache_server', action='store_true',
                        help="Disable the cache server on execution")
    parser.add_argument('-ddc', '--disable_docker_cache', action='store_true',
                        help="Disable docker cache.")
    parser.add_argument('--ca_cert', type=str, default=None,
                        help="Full path to CA certificate file that will contain the private key. "
                             "Default: <working directory>/certs/server_ca/cache_ca.pem. If non-existent it will be created.")
    parser.add_argument('--cache_dir', type=str, default=CACHE_DIRECTORY,
                        help="Full path to cache directory. Default: <working directory>/cache")
    parser.add_argument('--certs_dir', type=str, default=CERTS_DIRECTORY,
                        help="Full path to certificates directory. Default: <working directory>/certs")
    parser.add_argument('-sc_port', '--server_cache_port', type=int, default=CACHE_SERVER_PROXY_PORT,
                        help="Server cache port. Default: 3129")
    parser.add_argument('-dc_port', '--docker_cache_port', type=int, default=DOCKER_CACHE_REGISTRY_PORT,
                        help="Docker local registry cache port. Default: 3128. Caution: 3128 works out of the box with docker registry proxy image")
    parser.add_argument('-ipre', '--install_prerequisites', action='store_true',
                        help="Install prerequisites for the server to run.")
    parser.add_argument('-ccs', '--create_ubuntu_client_setting_script', type=str, default=None,
                        help="Full path to directory where ubuntu client installation bash scripts and required files will be stored. Default: <working directory>/client_files")
    return parser.parse_args()


if __name__ == '__main__':
    exec_args = parse_args()

    try:
        exit_result: int = run_servers_main(
            exec_args.disable_cache_server,
            exec_args.disable_docker_cache,
            exec_args.ca_cert,
            exec_args.cache_dir,
            exec_args.certs_dir,
            exec_args.server_cache_port,
            exec_args.docker_cache_port,
            exec_args.install_prerequisites,
            exec_args.create_ubuntu_client_setting_script
        )
    except KeyboardInterrupt:
        print("Exiting...")
        exit_result = 0

    sys.exit(exit_result)
