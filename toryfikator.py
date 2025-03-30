#!/usr/bin/env python3
import sys
import os
import subprocess
import requests
import socket

# Path to torrc – standard location in Kali Linux
TORRC_PATH = "/etc/tor/torrc"

# Configuration lines to be added to torrc by toryfikator
CONFIG_LINES = [
    "VirtualAddrNetworkIPv4 10.192.0.0/10",
    "AutomapHostsOnResolve 1",
    "TransPort 9040",
    "DNSPort 53",
    "TransListenAddress 127.0.0.1"
]

def print_help():
    """
    Print help message with available commands.
    """
    print("Usage: python3 toryfikator.py [command]")
    print("Commands:")
    print("  help         : Show this help message")
    print("  configure    : Check and add necessary entries in torrc")
    print("  start        : Check if Tor is running, verify torrc configuration, restart Tor and apply system torification")
    print("  stop         : Remove torification (iptables rules) and restore normal routing")
    print("  uninstall    : Remove toryfikator entries from torrc and remove iptables rules")
    print("  status       : Show Tor service status and public IP (indicating if it is a Tor IP)")

def configure_torrc():
    """
    Check and add necessary configuration lines in torrc.
    """
    if not os.path.exists(TORRC_PATH):
        print("torrc file not found at {}".format(TORRC_PATH))
        return
    try:
        with open(TORRC_PATH, 'r') as f:
            content = f.read()
    except Exception as e:
        print("Error reading torrc: {}".format(e))
        return

    added = False
    with open(TORRC_PATH, 'a') as f:
        for line in CONFIG_LINES:
            if line not in content:
                f.write("\n" + line)
                added = True
                print("Added configuration: {}".format(line))
    if not added:
        print("torrc is already configured.")
    else:
        print("torrc configuration updated.")

def check_torrc_config():
    """
    Verify that all required configuration lines exist in torrc.
    """
    if not os.path.exists(TORRC_PATH):
        return False
    try:
        with open(TORRC_PATH, 'r') as f:
            content = f.read()
    except Exception:
        return False

    for line in CONFIG_LINES:
        if line not in content:
            return False
    return True

def is_tor_running():
    """
    Check if Tor process is running.
    """
    try:
        subprocess.check_output(["pidof", "tor"])
        return True
    except subprocess.CalledProcessError:
        return False

def start_tor():
    """
    Check if Tor is installed.
    If Tor is already running, restart it.
    If not running, start it.
    """
    try:
        subprocess.check_output(["which", "tor"])
    except subprocess.CalledProcessError:
        print("Tor is not installed. Please install Tor.")
        return False

    if is_tor_running():
        print("Tor service is Running, restarting Tor...")
        try:
            subprocess.check_call(["service", "tor", "restart"])
            print("Tor restarted successfully.")
            return True
        except Exception as e:
            print("Failed to restart Tor: {}".format(e))
            return False
    else:
        try:
            subprocess.check_call(["service", "tor", "start"])
            print("Tor started successfully.")
            return True
        except Exception as e:
            print("Failed to start Tor: {}".format(e))
            return False

def rule_exists(table, chain, rule_args):
    """
    Check if the specified iptables rule exists.
    """
    try:
        subprocess.check_call(
            ["iptables", "-t", table, "-C", chain] + rule_args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return True
    except subprocess.CalledProcessError:
        return False

def get_ip(host):
    """
    Resolve host to IP.
    """
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None

def apply_iptables_rules():
    """
    Apply advanced iptables rules for torification:
      - Create the TORIFY chain if it does not exist.
      - Flush the TORIFY chain.
      - Add exclusion rules for local traffic and for the Tor process.
      - Add a rule to redirect all TCP traffic to port 9040.
      - Add a rule in the OUTPUT chain to direct TCP traffic to the TORIFY chain.
    """
    # Create the TORIFY chain if it does not exist.
    try:
        subprocess.check_call(
            ["iptables", "-t", "nat", "-L", "TORIFY"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
    except subprocess.CalledProcessError:
        subprocess.check_call(["iptables", "-t", "nat", "-N", "TORIFY"])
    
    # Flush the TORIFY chain.
    subprocess.check_call(["iptables", "-t", "nat", "-F", "TORIFY"])
    
    # Exclusion rules for local traffic and Tor process.
    exclusions = [
        ["-d", "127.0.0.0/8", "-j", "RETURN"],
        ["-d", "10.0.0.0/8", "-j", "RETURN"],
        ["-d", "172.16.0.0/12", "-j", "RETURN"],
        ["-d", "192.168.0.0/16", "-j", "RETURN"],
        ["-m", "owner", "--uid-owner", "debian-tor", "-j", "RETURN"]
    ]
    
    for rule in exclusions:
        if not rule_exists("nat", "TORIFY", rule):
            subprocess.check_call(["iptables", "-t", "nat", "-A", "TORIFY"] + rule)
    
    # Redirect all TCP traffic to port 9040.
    redirect_rule = ["-p", "tcp", "-j", "REDIRECT", "--to-ports", "9040"]
    if not rule_exists("nat", "TORIFY", redirect_rule):
        subprocess.check_call(["iptables", "-t", "nat", "-A", "TORIFY"] + redirect_rule)
    
    # Direct TCP traffic in OUTPUT to the TORIFY chain.
    output_rule = ["-p", "tcp", "-j", "TORIFY"]
    if not rule_exists("nat", "OUTPUT", output_rule):
        subprocess.check_call(["iptables", "-t", "nat", "-A", "OUTPUT"] + output_rule)
    
    print("Advanced iptables rules applied for torification.")

def remove_iptables_rules():
    """
    Remove torification rules:
      - Remove the TORIFY rule from the OUTPUT chain if it exists.
      - If the TORIFY chain exists, flush and delete it.
      - If the chain does not exist, indicate that no changes are needed.
    """
    output_rule = ["-p", "tcp", "-j", "TORIFY"]
    try:
        if rule_exists("nat", "OUTPUT", output_rule):
            subprocess.check_call(["iptables", "-t", "nat", "-D", "OUTPUT"] + output_rule)
    except subprocess.CalledProcessError:
        pass

    # Check if TORIFY chain exists.
    chain_exists = True
    try:
        subprocess.check_call(["iptables", "-t", "nat", "-L", "TORIFY"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        chain_exists = False

    if not chain_exists:
        print("No TORIFY chain found, no iptables changes needed.")
        return

    try:
        subprocess.check_call(["iptables", "-t", "nat", "-F", "TORIFY"])
        subprocess.check_call(["iptables", "-t", "nat", "-X", "TORIFY"])
        print("Advanced iptables rules removed, torification stopped.")
    except subprocess.CalledProcessError as e:
        print("Error removing iptables rules: {}".format(e))

def uninstall_torrc():
    """
    Remove toryfikator configuration from torrc.
    """
    if not os.path.exists(TORRC_PATH):
        print("torrc file not found at {}".format(TORRC_PATH))
        return
    try:
        with open(TORRC_PATH, 'r') as f:
            lines = f.readlines()
    except Exception as e:
        print("Error reading torrc: {}".format(e))
        return
    new_lines = []
    removed = False
    for line in lines:
        if any(config_line in line for config_line in CONFIG_LINES):
            removed = True
            print("Removed configuration: {}".format(line.strip()))
            continue
        new_lines.append(line)
    try:
        with open(TORRC_PATH, 'w') as f:
            f.writelines(new_lines)
        if removed:
            print("torrc configuration removed.")
        else:
            print("No toryfikator configuration found in torrc.")
    except Exception as e:
        print("Error writing torrc: {}".format(e))

def check_public_ip():
    """
    Check public IP and Tor service status via Tor Project API.
    """
    try:
        response = requests.get("https://check.torproject.org/api/ip", timeout=10)
        if response.status_code == 200:
            data = response.json()
            is_tor = data.get("IsTor", False)
            ip = data.get("IP", "Unknown")
            print("Tor service is Running")
            print("Public IP: {}".format(ip))
            print("Is Tor IP: {}".format(is_tor))
        else:
            print("Failed to get Tor check status. Status code:", response.status_code)
    except Exception as e:
        print("Error checking public IP via Tor API: {}".format(e))
        # Fallback: get public IP using ipify
        try:
            response = requests.get("https://api.ipify.org?format=json", timeout=10)
            if response.status_code == 200:
                data = response.json()
                ip = data.get("ip", "Unknown")
                print("Tor service is Down")
                print("Public IP: {}".format(ip))
                print("Is Tor IP: False")
            else:
                print("Failed to get public IP. Status code:", response.status_code)
        except Exception as e:
            print("Error checking public IP via ipify: {}".format(e))

def main():
    if len(sys.argv) < 2 or sys.argv[1] in ["help"]:
        print_help()
    else:
        cmd = sys.argv[1]
        if cmd == "configure":
            configure_torrc()
        elif cmd == "start":
            # Check torrc configuration first
            if not check_torrc_config():
                print("Missing torrc configuration. Please run 'python3 toryfikator.py configure' first.")
                return
            if not start_tor():
                return
            apply_iptables_rules()
        elif cmd == "stop":
            remove_iptables_rules()
        elif cmd == "uninstall":
            # Remove iptables rules first, then uninstall torrc configuration
            remove_iptables_rules()
            uninstall_torrc()
        elif cmd == "status":
            if is_tor_running():
                check_public_ip()
            else:
                print("Tor service is Down")
                remove_iptables_rules()  # Remove iptables if Tor is down.
                try:
                    response = requests.get("https://api.ipify.org?format=json", timeout=10)
                    if response.status_code == 200:
                        data = response.json()
                        ip = data.get("ip", "Unknown")
                        print("Public IP: {}".format(ip))
                        print("Is Tor IP: False")
                    else:
                        print("Failed to get public IP. Status code:", response.status_code)
                except Exception as e:
                    print("Error checking public IP:", e)
        else:
            print("Unknown command. Use 'help' to see available commands.")

if __name__ == "__main__":
    main()
