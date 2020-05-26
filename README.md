# Ansible
FortiGate Ansible Scripts
Preparing the demo:
- Make sure you are using Ansible 2.9.x and you have installed the Ansible FortiOS Galaxy Collection:
	- https://galaxy.ansible.com/fortinet/fortios

Rename the files like this:
- demo1.yaml.txt rename to demo1.yaml
- demo2.yaml.txt rename to demo2.yaml
- hosts.txt rename to hosts

To run Demo 1 scenario execute:
	ansible-playbook -i hosts demo1.yaml

To run Demo 2 scenario execute:
	ansible-playbook -i hosts demo2.yaml --extra-vars "srv_name=WebSrv12 srv_address=12.12.12.12 srv_vip=50.50.50.50 srv_pub_interface=port8 policy_id=100 srv_interface=port9"
