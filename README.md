# roger_skyline
how to build a linux webserver

VM part
- Run a linux VM on a hypervisor (e.g. virtualbox) of your choice - DONE
- Should have an 8 gb disc space - DONE (sudo fdisk -l | less) & (lsblk)  
- Should have at least one partition of 4.2 gb - DONE
- Should be up to date and have all the packages needed to meet the demands of the subject - DONE

Network & security part
- Create a non-root user to connect to the machine and work - DONE
- Use sudo, while connected as that user, to do something requiring special rights - DONE

sudo adduser <username>
awk -F: '{ print $1}' /etc/passwd (to check user was added)
sudo user mod -aG sudo <username>
su - <username>
(Try a command like sudo fdisk -l)

- Dont use the DHCP service of the machine, configure with static IP and netmask \30 - DONE

DHCP = Dynamic Host Configuration Protocol - automatically provides and assigns IP addresses, default gateways and other network params. Without it, every client joining the network would have to be manually set-up, which could be cumbersome on large networks.
Static IP = an IP address that DOES NOT CHANGE. Generally used by servers because it makes them a lot easier to find with a DNS lookup (e.g. a website address will be connected to a permanent IP address).
The subnet mask lets us know the number of bits available to be used as host IP addresses. With a mask of 30, there are only 2 bits available to make valid IP addresses with (0-3). As one will be reserved as the subnet ID, and one as the broadcast address, this leaves only 2 valid IP addresses to use. The benefit is that this means we can have a larger number of subnets in our network in total. (see subnet-calculator.com for reference)

// the below sets up a host only static IP which will not allow us the internet access needed to update our VM
In order to set up the static IP, we must first create a new network adapter in virtualbox, which we set to host-only.
First we go to global tools and create a new adapter, which will be called vboxnet0, and uncheck enable under DHCP server.
In settings we can then set up adapter 2 (while VM is powered down) and set this to Host-Only (i.e. the socket will only connect with the machine the VM is hosted on) and select vboxnet0

(NB: “ifconfig -a” to check IP address. Once the host-only adapter is set up, details for enp0s8 should also appear)

// the following will allow us internet access and create a static IP
Go to network settings in virtual box and set the adapter to “Bridged Adapter”
Check find default gateway by using the following command in terminal:

route get default

In our case this is:

10.11.245.254

We then need to change our netplan config file inside our VM:

cat /etc/netplan/00-installer-config.yaml //displays the network config, “dhcp4: true” by default

this file needs to be changed to the following (sudo vim <file path>):

network:
  ethernets:
    enp0s3: 								
      addresses: [10.11.254.253/30] 	//this is our static IP address and /30 subnet mask (confirmed on online IP calc)
      gateway4: 10.11.245.254			//this is the default gateway for connections to the machine
      nameservers:
        addresses: [8.8.8.8,8.8.4.4]	//nameserver (DNS) returns the IP address/Default gateway
  version: 2

we then apply our changes in command line, then reboot the server and test:

sudo netplan apply

For testing, we can do a couple of things. A standard ifconfig check will show our enp0s8 updated with our static IP details. We can also ping our static IP address to check it is returning data. Furthermore, we can ssh directly into our static IP, on our host machine, without having to tunnel through the network with port-forwarding via our NAT adapter:

ssh amann@10.11.254.253

- Change the default port of the SSH service to the one of your choice. SSH must be done with publickeys. SSH root access should not be allowed directly, but with a user who can be root. - DONE

ssh config file path: /etc/ssh/sshd_config

The default port that sshd listens on is 22, this is communicated to us via a comment in the config file (NB default values in the config are commented out, as a rule):

#Port 22

We can simply remove this line and change the number to something unique (best to make the following changes directly in the VM, rather than via ssh):

sudo vim /etc/ssh/sshd_config
change “#Port 22” to “Port 1234” then save and exit vim (esc ZZ)
sudo systemctl reload sshd //reloads sshd service

We might want to do this if we have multiple servers with the same IP address, but a bigger reason would be security. Obscuring the SSH port by setting it to a unique number will make it less likely to be targetted by attackers. Bots scanning the web for open SSH servers will not find yours as easily.

To test, we can SSH into our VM again. NB we now have to use the -p flag to specify our unique port, or it will default back to 22 and just hit a closed port:

ssh -p 1234 amann@192.168.56.2

NB: If you’re running a firewall, you’ll need to reconfigure it to allow traffic to the unique port.

To disable ssh as root:

sudo vim /etc/ssh/sshd_config
change “#PermitRootLogin yes” to “PermitRootLogin no” then save and exit vim (esc ZZ)

So, public keys…

SSH is a way of encrypting a connection between two machines. We set this up by creating a pair of keys, a private key and a public key. Messages encrypted by the public key can be decrypted by the private key, and vice versa. They are usually stored on your computer in ~/.ssh/id_rsa (private) and ~/.ssh/id_rsa.pub (public)

We can log into our VM, go to the ~/.ssh/authorized_keys file and add the public key from our machine, which will allow us to make an ssh connection from that machine.

NB: if SSH cannot connect, try changing the port number, apply netplan again, systemctl reload ssh again, reboot machine, and try connecting to new port.

- Set rules on your firewall with the services used outside the VM - DONE

As mentioned in the section above, with ufw enabled (ubuntu server’s built in fire wall), we will have to set a rule to allow access to port 1234.

sudo ufw enable
sudo ufw allow 1234
sudo ufw status

The final command should display 1234 with action: ALLOW from: Anywhere.

Also, block all IPV6 connections with the following:

sudo vim /etc/ufw/ufw.conf

Then add the line: 

IPV6=no 

This will stop any IPv6 addresses creeping through the open port.

- Set DOS (Denial Of Service Attack) protection on the open ports of the VM - DONE 

Fail2ban can be installed with the following command line:
sudo apt update
sudo apt install fail2ban

Fail2ban uses regex to scan logfiles. It can be used to protect a linux server from brute-force and other forms of attacks and malicious activity. When certain thresholds are reached, the offending IP address is banned, using the system firewall, for a specific period of time.

Once installed, it will be up and running automatically, check the status with the following command line:
sudo systemctl status fail2ban

config files in fail2ban are read in the following order:
/etc/fail2ban/jail.conf
/etc/fail2ban/jail.d/*.conf
/etc/fail2ban/jail.local
/etc/fail2ban/jail.d/*.local

The easiest way to configure fail2ban is to copy contents of jail.conf into jail.local, and simply modify the latter. (create the file if it’s not present, dont update the .conf file as changes will be lost when the package is updated). Use the following command line:

touch jail.local //if file does not exist
sudo cp jail.{conf,local}

The important things to edit are:

ignoreip = <ip addresses> 	//whitelists specified IP addresses, i.e. they cannot be banned from connecting
bantime = 1m					//sets the length of time an IP address is banned from connecting to the server. Negative = perma-ban
findtime = 1m					//sets the duration within which the failed attempts must occur
maxretry = 3					//sets the number of failed logins before an IP is banned

each time a config file is editted, the fail2ban service should be restarted:

sudo systemctl restart fail2ban

Check banned currently banned IPs with the following CL:

sudo fail2ban status sshd

- Set protection against scans on your VM’s open ports

PortSentry is a daemon that will watch open ports for unusual activity, and, depending on how it’s configured, will take actions against it. Often, before an intrusion attempt, hackers will scan a server’s ports to check for weaknesses. PortSentry can be figured to block the IP address conducting scans, thus preventing further scanning or intrusion attempts.

sudo apt-get update							//sync packages with most up to date resources
sudo apt-cache search “portsentry”		//displays info about portsentry
sudo apt-get install portsentry			//installs portsentry
ls -l /etc/portsentry						//confirms installation worked

we will use the file at the following path to configure portsentry. NB portsentry.ignore and portsentry.ignore.static can be used to whitelist specific IP addresses: 

/etc/portsentry/portsentry.conf

grep portsentry /var/log/syslog 	//reveals portsentry is already listening on various TCP/UDP ports

find /etc/rc*.d/* -print | xargs ls -l | grep portsentry //identifies the startup and kill scripts for portsentry

runlevel 	//identifies the current run level (0 = system Halt, 1 = single user, 2 - 5 = multi-user (default), 6 = system reboot

To stop portsentry:

cd /etc/init.d
./portsentry stop
ps -eaf | grep -v grep | grep portsentry | wc -l        //0 should be returned
./portsentry start
ps -eaf | grep -v grep | grep portsentry	      //2 lines should be returned

nmap can be installed into another vm to scan the ports and check that it is working:

nmap -p 1-65535 -T4 -A -v -PE -PS22,25,80 -PA21,23,80 <vm with portsentry IP>

This will list off some information regarding the scanned ports of our vm. We can then check the /var/log/syslog for attackalert to confirm the scanning was noticed. 

Howwever, no action will be taken unless we update our portsentry config file:

grep -n “BLOCK_UDP=“ /etc/portsentry/portsentry.conf  //in our case this on line 135
vim +135 /etc/portsentry/portsentry.conf
change 0 to 1 for UDP and TCP, then save and quit.
sudo service portsentry stop
sudo service portsentry start

Now we can scan again, and then try to ping the same IP and we shouldn’t be able to reach it. We can also check /etc/hosts.deny to see if the other machine’s IP is blocked.

- Stop the services not needed for the project - DONE

to check which services are active:

systemctl —-type=service -—state=active

accounts-daemon			- manages user accounts 
apparmor 				- needed for kernel to work
apport					- collects potentially sensitive system date, e.g. core dumps, stack traces, things that could contain passwords etc.
atd						- job scheduler, similar to cron
blk-availability			- needed for system memory management
console-setup			- Sets keymapping and fonts in console
cron						- manages timed tasks
dbus					- allows programs to communicate with eachother
finalrd					- helps with shutdown process
getty@ttty				- handles terminal/CLI
keyboard-setup			- Works with console-setup to organise keymapping
kmod-static-notes			- systemd related
lvm2-monitor				- monitors the kernel device mapper
mutlipathd				- Daemon that checks for failed pathways, which will reconfigure the map when it finds one, maximising performance (server connections)
networkd-dispatcher		- dispatcher daemon for systemd
polkit					- Authorisation manager
rsyslog					- System logging service
setvtrgd					- sets console scheme
snapd					- introduced by canonical to allow developers to more easily distribute their applications
ssh						- needed for ssh connections
systemd…				- all linux essentials
udisks2					- Disk manager
ufw						- firewall
unattended-upgrades		- Keeps system current with latest security updates
user-runtime-dir@1000	- runtime directory for UID 1000 (i.e. amann)
user@1000				- user mannager for UID 1000 (i.e. amann) 

for definition of service:
systemctl cat <servicename>.service

Cloud services aren’t needed, so we can disable those by simply creating a .disabled file in the relevant dir, and reboot:

touch /etc/cloud/cloud-init.disabled

ModemManager isn’t really needed, it controls interfaces with mobile broadband (eg 4G). We ain’t using 4G in this project, so we can mask it to prevent it from starting, then reboot to check it worked:

sudo systemctl mask ModemManager.service

- Create a script to update all the sources of package, then your packages and logs the whole thing in a file named /var/log/update_script.log Create a scheduled task to run the script once a week at 4am and when the machine reboots. - DONE

To schedule a task, open and edit the crontab. Using sudo will open the root user crontab, so commands apply to everything:

sudo crontab -e

tasks are scheduled with the following syntax (wildcards apply, i.e. * = every/any): minute(0-59) hour(0-23) day(1-31) month(1-12) weekday(0-6) command

so, in order to schedule a script to run once a week @ 4am:

0 4 * * 1 sh /home/amann/scripts/update.sh

and on reboot:

@reboot sh <path to script>

NB: /home/<username>/etc… is needed to find our script, as it will be ran as root. 

our update script will look like this:

#!/bin/bash

WRITE_TO_LOG=“tee -a /var/log/update_script.log”

date | $WRITE_TO_LOG
apt update | $WRITE_TO_LOG			//NB no ‘sudo’ needed as script will run as root 
apt upgrade | $WRITE_TO_LOG

Including the date helps to identify what ran and when, if we check our log.
ensure the script is set to executable (chmod 777 update.sh) and file starts with the line: #!/bin/bash

- Create a script to monitor changes to the /etc/crontab file and sends an email to the root if it has been modified. Create a scheduled script task every day at midnight - DONE

sudo apt install mailutils -y
sudo apt install sendmail -y

The above packages allow us to send emails in the command line. We then need to put together a bash script to check if it was modified in the last 24hrs:

#!/bin/bash

FILE=“/etc/crontab”
MESSAGE=“The root crontab file was changed in the last 24hrs”
EMAIL=“alex.mann1989@gmail.com”
CUR_TIME=$(date +%s)
ONE_DAY=“86400”
TIME=$(($CUR_TIME - $ONE__DAY))
MOD_TIME=$(stat -c ‘%X’ $FILE)

if [ $TIME -lt $MOD_TIME ]
then
	echo $MESSAGE | mail -s “ALERT!” $EMAIL
fi

Then, update the root crontab with the following line to run the script at midnight everyday:

0 0 * * * sh /home/amann/scripts/update.sh

NB: if the machine is not running, the cron jobs will not be triggered. Look into anacron (man anacron) if you’d like them to run when the machine is restarted. This is installed by default and is how ubuntu handles jobs in /etc/cron.{daily,weekly,monthly}
