# Alteration of sshd_config file

## Metadata

- **UUID**: `b32ced71-138b-4076-8376-4f13161af4b0`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
This threat vector highlights the risk associated with unauthorized access or 
alteration of the `sshd_config` file on Linux systems. Adversaries who manage 
to gain elevated privileges (root or sudo) can modify SSH service parameters 
in `sshd_config` to allow additional keys, redirect ports, or weaken 
authentication requirements.  

Possible scenario done by a threat actor :

### Adding Rogue SSH Keys
An attacker with root or sudo privileges could append a malicious public key to 
the authorized_keys directive in sshd_config. For instance:

```bash
echo "AuthorizedKeysFile /etc/ssh/my_malicious_keys" >> /etc/ssh/sshd_config
```
They might then place their public key in that file. This allows them to log in 
via SSH without needing a password, often bypassing standard detection.  

### Enabling Root Login
If an organization has wisely disabled direct root login, an attacker could revert 
that setting in sshd_config:

```bash
sed -i 's/^#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
```
By doing so, they allow themselves to authenticate as root directly.  

### Allowing Password Authentication
In secure environments, SSH often requires key-based authentication. 
An attacker might weaken this by enabling password-based access and choosing 
easy-to-guess credentials:

```bash
sed -i 's/^PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
```
Once changed, brute-force or credential-stuffing techniques become more feasible, 
helping the adversary maintain illicit access.  

### Redirecting SSH Ports
Defenders commonly monitor TCP port 22 for suspicious activities. An attacker 
could modify sshd_config to run SSH on a high or less-monitored port:

```bash
sed -i 's/^Port 22/Port 2222/' /etc/ssh/sshd_config
```
This tactic helps attackers blend into legitimate traffic patterns or bypass 
perimeter defenses that only monitor the default SSH port.  

### Creating Hidden Backdoors
Attackers may add an additional Match block in sshd_config that grants special 
privileges to a specific user or from a specific IP range:

```bash
echo "Match User hiddenuser
    X11Forwarding yes
    AllowTcpForwarding yes" >> /etc/ssh/sshd_config
```
This configuration could stealthily enable features like port forwarding, 
further helping attackers evade detection and maintain persistence.

## Techniques
- T1098.004
