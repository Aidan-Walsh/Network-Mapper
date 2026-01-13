# RUN ONLY ON PIVOT
nano /etc/ssh/sshd_config #(change pass auth to yes)
sudo adduser student
sudo usermod -aG sudo student
sudo systemctl restart sshd
sudo apt update
apt install nmap
apt install proxychains
apt install proxychains4
apt install sshpass