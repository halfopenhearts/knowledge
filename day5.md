Linux boot process
================

General Info
------------

Host: MATTHEW_WILLIS  
IP: 10.50.15.85  

Task:
- 

Focus:
- grub - persistence - /boot/grub/x86_64-efi/normal.mod + grub.cfg
- 




/dev/vda - boot record

examine mbr with ; sudo xxd -l 512 -g /dev/dva

always copy mbr with ; dd if=/dev/vda of=MBRcopy bs=512 count =1
file MBRcopy


erfi lives in /efo/ubuntu/grubx64.efi

lsmod - whats in the kernel
ltrace - real time kernel requests | modular , loads a list of items


start pid 1 - if pid 1 does the system reboots or panics
pid 1 launches /sbin/init
run level directories /etc/rc#.d contains scripts to start/stop daemons
scripts here run as root during boot - high value persistence

systemctl list-dependecies graphical.target

systemctl show -p wants graphical.target

systemctl cat display-manager.service


ls -l /bin/systemd/system/default.target

systemctl cat geaphical.target



bashrc runcs at boot not login





know systemd vs sysv - find persistence quickly

