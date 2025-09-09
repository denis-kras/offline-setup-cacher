# Offline Setup Cacher

## Overview
Offline Setup Cacher is a tool that allows you to cache the installation files of various software packages for offline installation. It is particularly useful for environments with limited or no internet access. Built for Ubuntu, it can be adapted for other Linux distributions with some modifications.

## How it works: Basics
1. You set up a local server that will run this script that will cache and then serve the cached installation files.
2. Then set the client host to use this server as a proxy to install the software packages.
3. Disconnect the server from the internet and take it to the offline environment.
4. Run the same installation on another client that is connected to the same offline network environment as the cache server.

## Tested
The server was tested with Ubuntu 24.04 LTS and python 3.12.
The client software that was tested:
- apt
- pip
- python requests
- docker, docker BuildKit
- curl, wget (downloading files from urls directly, repos from github.com are supported + 302 requests)
- npm
- sudoers

Probably it will work with anything HTTP/HTTPS related, but I haven't tested it with other software or methods.

## Requirements
You don't need anything special to install this script on the server. You do need Ubuntu 24.04 LTS, and it was tested with Python 3.12.

## Execution
### Ubuntu Server (Desktop version that will act as a server)
Note: all the commands below are to run in the terminal.
1. Set the file as executable:
    ```bash
    chmod +x offline_setup_cacher.sh
    ```
2. Run the script:
    ```bash
    ./offline_setup_cacher.py
    ```
3. You can also run the script with `--help` to see all the options available.
4. By default, the client install/uninstall scripts will be created in the `./client_scripts` directory. You can change this by using the `-cfd /your/client/files/path` option.
Note: the client scripts are `client_install.sh`, `client_uninstall.sh` and the CA certificate file.
`client_install.sh` will install the CA certificate, set caching server IP as the proxy for the system.

### Ubuntu Client
1. Get the files from the server in the `./client_scripts` directory and copy them to the client machine.
2. Set the file as executable:
    ```bash
    chmod +x client_install.sh
    ```
3. Run the script:
    ```bash
    ./client_install.sh
    ```
   If you want the proxy to be available also in the same terminal session right awaym you can execute the command with `source`:
    ```bash
    source client_install.sh
    ```
   or
    ```bash
    . client_install.sh
    ```
   For the `source` command to work you don't need to set the file as executable.
4. If you want to remove all the changes that `client_install.sh` made and remove the custom CA certificates, you can run the `client_uninstall.sh` script:
    ```bash
    chmod +x client_uninstall.sh
    ```
    ```bash
    ./client_uninstall.sh
    ```