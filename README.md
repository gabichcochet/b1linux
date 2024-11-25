# b1linux


# Étape 1 : Analyse et nettoyage du serveur

## Lister les tâches cron pour détecter des backdoors :

````
[root@localhost ~]# sudo grep CRON /var/log/cron
````

## Identifier et supprimer les fichiers cachés :

````
[root@localhost ~]# ls -alh /tmp
-rwxrwxrwx.  1 attacker attacker   18 Nov 24 18:24 .hidden_file
-rwxrwxrwx.  1 attacker attacker   17 Nov 24 18:11 .hidden_script
-rwxr-xr-x.  1 attacker attacker   23 Nov 24 18:11 malicious.sh
````

```` 
[root@localhost ~]# ls -alh /home
drwx------. 2 attacker attacker 4.0K Nov 24 20:09 ..
````

````
[root@localhost ~]# ls -alh /var/tmp
-rwxrwxrwx.  1 attacker attacker    7 Nov 24 20:10 .nop
````

````
[root@localhost ~]# sudo rm -r /home/attacker
[root@localhost ~]# sudo rm /tmp/.hidden_file
[root@localhost ~]# sudo rm /tmp/.hidden_script
[root@localhost ~]# sudo rm /tmp/.malicious.sh
[root@localhost ~]# sudo rm /var/tmp/.nop
````

## Analyser les connexions réseau actives :

````
[root@localhost ~]# sudo ss -tunap
Netid   State    Recv-Q   Send-Q            Local Address:Port      Peer Address:Port   Process
udp     ESTAB    0        0          192.168.147.3%enp0s8:68       192.168.147.2:67      users:(("NetworkManager",pid=866,fd=33))
udp     ESTAB    0        0              10.0.2.15%enp0s3:68            10.0.2.2:67      users:(("NetworkManager",pid=866,fd=26))
udp     UNCONN   0        0                     127.0.0.1:323            0.0.0.0:*       users:(("chronyd",pid=862,fd=5))
udp     UNCONN   0        0                         [::1]:323               [::]:*       users:(("chronyd",pid=862,fd=6))
tcp     LISTEN   0        128                     0.0.0.0:22             0.0.0.0:*       users:(("sshd",pid=901,fd=3))
tcp     ESTAB    0        0                 192.168.147.3:22       192.168.147.1:52132   users:(("sshd",pid=1916,fd=4),("sshd",pid=1912,fd=4))
tcp     LISTEN   0        128                        [::]:22                [::]:*       users:(("sshd",pid=901,fd=4))
````

# Étape 2 : Configuration avancée de LVM

## Créer un snapshot de sécurité pour /mnt/secure_data :

````
[root@localhost ~]# sudo lvcreate --size 10.00m --snapshot --name snap /dev/vg_secure/secure_data
````

## Tester la restauration du snapshot :

````
[root@localhost ~]# ls /mnt/secure_data
lost+found  sensitive1.txt
[root@localhost ~]# rm /mnt/secure_data/sensitive2.txt
rm: remove regular file '/mnt/secure_data/sensitive2.txt'? yes
[root@localhost ~]# sudo mkdir /mnt/snapshot
[root@localhost ~]# sudo mount /dev/vg_secure/snap /mnt/snapshot
[root@localhost ~]# cp /mnt/snapshot/sensitive2.txt /mnt/secure_data/
[root@localhost ~]# sudo umount /mnt/snapshot
````


## Optimiser l’espace disque :

````
[root@localhost ~]# lvextend --size +10.00m /dev/vg_secure/secure_data
  Rounding size to boundary between physical extents: 12.00 MiB.
  Size of logical volume vg_secure/secure_data changed from 500.00 MiB (125 extents) to 512.00 MiB (128 extents).
  Logical volume vg_secure/secure_data successfully resized.
````

# Étape 3 : Automatisation avec un script de sauvegarde

## Créer un script secure_backup.sh :

````
[root@localhost ~]# sudo nano /usr/local/bin/secure_backup.sh
````

## Ajoutez une fonction de rotation des sauvegardes :

````
#!/bin/bash

# Variables
SOURCE_DIR="/mnt/secure_data"
BACKUP_DIR="/backup"
DATE=$(date +%Y%m%d_%H%M)
BACKUP_FILE="$BACKUP_DIR/secure_data_$DATE.tar.gz"
MAX_BACKUPS=7
LOG_FILE="/var/log/backup.log"

# Création de l'archive en excluant les fichiers temporaires et cachés
tar --exclude='*.tmp' --exclude='*.log' --exclude='.*' -czf "$BACKUP_FILE" -C "$SOURCE_DIR" . >> "$LOG_FILE" 2>&1

# Fonction de rotation des sauvegardes
rotate_backups() {
    cd "$BACKUP_DIR" || exit
    if [ $(ls -1 | wc -l) -gt $MAX_BACKUPS ]; then
        ls -tp | grep -v '/$' | tail -n +$((MAX_BACKUPS + 1)) | xargs -I {} rm -- {}
    fi
}

# Appel de la fonction de rotation
rotate_backups

echo "Sauvegarde créée : $BACKUP_FILE" >> "$LOG_FILE"
````

## Testez le script :

````
[root@localhost ~]# sudo chmod +x /usr/local/bin/secure_backup.sh
````

````
[root@localhost ~]# sudo /usr/local/bin/secure_backup.sh
[root@localhost ~]# ls /backup
secure_data_2024111227.tar.gz     secure_data_20241125_1230.tar.gz  secure_data_20241125_1232.tar.gz  secure_data_20241125_1234.tar.gz
secure_data_20241125_1229.tar.gz  secure_data_20241125_1231.tar.gz  secure_data_20241125_1233.tar.gz
````

# Étape 4 : Surveillance avancée avec auditd


## Configurer auditd pour surveiller /etc :

````
[root@localhost ~]# sudo auditctl -w /etc -p wa -k etc_changes
Old style watch rules are slower
````

````
[root@localhost ~]# sudo auditctl -l
-w /etc -p wa -k etc_changes
````

## Tester la surveillance :

````
[root@localhost ~]# sudo touch /etc/testfil
````

````
time->Mon Nov 25 15:03:01 2024
type=PROCTITLE msg=audit(1732543381.284:2343): proctitle=746F756368002F6574632F7465737466696C
type=PATH msg=audit(1732543381.284:2343): item=1 name="/etc/testfil" inode=33596 dev=fd:00 mode=0100644 ouid=0 ogid=0 rdev=00:00 obj=unconfined_u:object_r:etc_t:s0 nametype=CREATE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=PATH msg=audit(1732543381.284:2343): item=0 name="/etc/" inode=18 dev=fd:00 mode=040755 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:etc_t:s0 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=CWD msg=audit(1732543381.284:2343): cwd="/root"
type=SYSCALL msg=audit(1732543381.284:2343): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7ffffe5b78f0 a2=941 a3=1b6 items=2 ppid=5102 pid=5104 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=75 comm="touch" exe="/usr/bin/touch" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key="etc_changes"
````

## Analyser les événements :

````
[root@localhost ~]# sudo ausearch -k etc_changes > /var/log/audit_etc.log
````

````
[root@localhost ~]# sudo firewall-cmd --permanent --add-service=ssh
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
````

# Étape 5 : Sécurisation avec Firewalld

## Configurer un pare-feu pour SSH et HTTP/HTTPS uniquement :

````
sudo firewall-cmd --set-default-zone=drop
````

## Bloquer des IP suspectes :

````
[root@localhost ~]# sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.168.1.100" reject'
success
````

````
[root@localhost ~]# sudo firewall-cmd --reload
success
[root@localhost ~]# firewall-cmd --list-all
drop (active)
  target: DROP
  icmp-block-inversion: no
  interfaces: enp0s3 enp0s8
  sources:
  services: http https ssh
  ports:
  protocols:
  forward: yes
  masquerade: no
  forward-ports:
  source-ports:
  icmp-blocks:
  rich rules:
        rule family="ipv4" source address="192.168.1.100" reject
````

## Restreindre SSH à un sous-réseau spécifique :

````
[root@localhost ~]# sudo nano /etc/ssh/sshd_config
````

````
#       $OpenBSD: sshd_config,v 1.104 2021/07/02 05:11:21 dtucker Exp $

# This is the sshd server system-wide configuration file.  See
# sshd_config(5) for more information.

# This sshd was compiled with PATH=/usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin

# The strategy used for options in the default sshd_config shipped with
# OpenSSH is to specify options with their default value where
# possible, but leave them commented.  Uncommented options override the
# default value.

# To modify the system-wide sshd configuration, create a  *.conf  file under
#  /etc/ssh/sshd_config.d/  which will be automatically included below
Include /etc/ssh/sshd_config.d/*.conf
AllowUsers *@192.168.147.0/24
````

````
[root@localhost ~]# sudo systemctl restart sshd
````