Issue the following commands to get this image up and running

docker build -t network-target .
docker run --name target --rm -it -p "8888:8888" -v log:/log -v node:/opt/node network-target
