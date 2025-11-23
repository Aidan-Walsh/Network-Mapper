# configuration to run on all machines which adds sudo user "student"
# this is only necessary if there is no ssh enabled with passwords and no users
# are added to the internal networks
nano /etc/ssh/sshd_config #(change pass auth to yes)
sudo adduser student
sudo usermod -aG sudo student
sudo systemctl restart sshd
sudo sysctl -w net.ipv4.ip_forward=0 