Issue the following commands to get this image up and running (UDP scanning port 4000 of target)

docker build -t port-scanner .
docker run --name scanner --rm -v log:/log -v scanner-config:/config -it --link=target port-scanner -sU -p 4000 target
