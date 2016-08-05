Issue the following commands to get this image up and running (issuing a UDP attack against "target:4000")

docker build -t bonesi-attacker .
docker run --name attacker --rm -v log:/log -v config:/bonesi-master/config --link=target -it bonesi-attacker --protocol=udp target:4000


Run a HTTP GET/TCP attack against target:8888 over network device eth0
docker run --name attacker --rm -v log:/log -v config:/bonesi-master/config --link=target -it bonesi-attacker --protocol=tcp -d eth0 target:8888
