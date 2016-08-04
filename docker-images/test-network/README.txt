docker-compose configuration to setup a Probe-Scanner-Attacker container network.

Install docker-compose:
	https://docs.docker.com/compose/install/

Run docker-compose from this directory to install apps in network:
	sudo docker-compose up -d

Installer docker-compose-ui (for ease of monitoring and managing network; run from this directory):
	sudo docker run --name docker-compose-ui --rm -p 5000:5000 -v /var/run/docker.sock:/var/run/docker.sock -v `pwd`:/opt/docker-compose-projects:ro --net testnetwork_default francescou/docker-compose-ui:0.19.0

