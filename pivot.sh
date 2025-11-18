# RUN ONLY ON PIVOT
# Nano /etc/ssh/sshd_config (change pass auth to yes)
sudo adduser student
sudo usermod -aG sudo student
sudo systemctl restart sshd
Sudo apt update
apt install nmap
apt install proxychains