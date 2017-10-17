This is a simple program allows a host machine to connect to routers via SSH and configure them
The python module used for this is paramiko

The IP Addresses of the routers to be configured are in the text file called ssh_ip.txt
The username and password for the login are in ssh_userpass.txt
The commands that are run on the router are in the ssh_commands.txt

The program makes use of threading to SSH all the routers simultaneouly


The topology of the network is in file named Topology