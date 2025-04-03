# Toryfikator

Toryfikator is a Python 3 utility for routing all your system traffic through Tor on Kali Linux. The program configures both Tor and iptables to transparently redirect TCP traffic through Tor’s network, helping to anonymize your network communications.

![Dragon Eats Onion](dragoneatsonion.webp)

## Features

- **Tor Configuration:**  
  Automatically checks and updates your `/etc/tor/torrc` file with the necessary configuration lines:
  - `VirtualAddrNetworkIPv4 10.192.0.0/10`
  - `AutomapHostsOnResolve 1`
  - `TransPort 9040`
  - `DNSPort 53`
  - `TransListenAddress 127.0.0.1`

- **Iptables Management:**  
  Applies advanced iptables rules to redirect all TCP traffic through port 9040 while excluding local traffic and the Tor process itself. Also, it safely removes the rules when needed.

- **Service Control:**  
  The utility checks if the Tor service is running. If it is, the program restarts Tor to load any new configuration; if not, it starts Tor automatically.

- **Status Reporting:**  
  Displays the public IP and indicates whether the Tor service is running (e.g., "Tor service is Running" or "Tor service is Down"). When Tor is down, the program also removes the iptables rules to restore normal routing.

## Requirements

- Python 3
- Root privileges (required to modify iptables and Tor configuration)
- The `requests` library (python3-requests)
- Tor package installed 

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/toryfikator.git
   cd toryfikator

2. Install the required Python package:
	```bash
	sudo apt install python3-requests
	```

## Usage

Run the script with the following commands:

- **Show Help:**

  ```bash
  sudo python3 toryfikator.py help
  ```

  Displays the help message with a list of available commands and usage instructions.

- **Configure Tor:**

  ```bash
  sudo python3 toryfikator.py configure
  ```

  Checks your `/etc/tor/torrc` file and adds the required configuration lines if they are missing.

- **Start Torification:**

  ```bash
  sudo python3 toryfikator.py start
  ```

  - Verifies the configuration in `torrc` (if missing, you’ll be prompted to run the `configure` command).
  - Checks if the Tor service is running; if it is, the script restarts it to load any changes.
  - Applies the iptables rules to route all TCP traffic through Tor.

- **Stop Torification:**

  ```bash
  sudo python3 toryfikator.py stop
  ```

  Removes the iptables rules and restores normal network routing.

- **Uninstall Configuration:**

  ```bash
  sudo python3 toryfikator.py uninstall
  ```

  Removes the iptables rules and deletes the Toryfikator-related configuration lines from `torrc`.

- **Check Status:**

  ```bash
  sudo python3 toryfikator.py status
  ```

  Displays the Tor service status and the current public IP, indicating if the IP is coming through Tor.

## Notes

- **Permissions:**
   Since the program modifies system configurations and iptables, it must be run as root (using `sudo`).
- **System Compatibility:**
   This utility is designed for Kali Linux environments. Paths and service management (using `service tor start/restart`) are tailored to such systems.
- **Detailed iptables Modifications:**  
    The script modifies iptables as follows:
    - **Chain Creation:** Creates a new chain called `TORIFY` in the `nat` table if it does not already exist.
    - **Chain Flushing:** Flushes the `TORIFY` chain to remove any existing rules.
    - **Exclusion Rules:** Adds rules to exclude traffic destined for local networks (e.g., `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and traffic from processes owned by `debian-tor` from redirection.
    - **Traffic Redirection:** Adds a rule to redirect all TCP traffic to port `9040` using the `REDIRECT` target.
    - **OUTPUT Chain Rule:** Inserts a rule in the `OUTPUT` chain of the `nat` table to forward TCP traffic to the `TORIFY` chain.

### Disclaimer

This project is intended solely for testing onion applications and is not designed to provide complete anonymity. If you require robust anonymity, please consider using [Tails](https://tails.net/) or [Whonix](https://www.whonix.org/). This tool is provided as my alternative implementation to existing projects such as [kali-anonsurf](https://github.com/Und3rf10w/kali-anonsurf), [ToriFY](https://github.com/Debajyoti0-0/ToriFY), and [kalitorify](https://github.com/brainfucksec/kalitorify).

## Contributing

Feel free to fork this repository and submit pull requests. Any enhancements, bug fixes, or improvements are welcome!
