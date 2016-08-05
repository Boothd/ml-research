docker-compose configuration to setup a Target-Pinger-Scanner-Attacker network.

Install docker-compose:
	https://docs.docker.com/compose/install/

Run docker-compose from this directory to install apps in network:
	sudo docker-compose up -d

Installer docker-compose-ui (for ease of monitoring and managing network; run from this directory):
	sudo docker run --name docker-compose-ui -d -p 5000:5000 -v /var/run/docker.sock:/var/run/docker.sock -v `pwd`:/opt/docker-compose-projects:ro --net testnetwork_default francescou/docker-compose-ui:0.19.0


Find your docker volumes containing config/log/code files
	sudo docker volume ls
	sodo docker volume inspect testnetwork_log
	sodo docker volume inspect testnetwork_config
	sodo docker volume inspect testnetwork_node-target
	sodo docker volume inspect testnetwork_node-pinger


Launch an nmap port scan at the target, e.g. for UDP against port 4000
	sudo docker-compose run scanner -sU -p 4000 target


Launch a BoNeSi attack at the target, e.g. using UDP against port 4000
	sudo docker-compose run attacker --protocol=udp target:4000



URLs for monitoring activity:
	docker-compose-ui:	http://localhost:5000/
	target activity:	http://localhost:8888/attackcount
	pinger activity:	http://localhost:8866/

