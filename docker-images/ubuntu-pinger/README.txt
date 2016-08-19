Issue the following commands to get this image up and running

docker build -t network-pinger .
docker run --name pinger --rm -p "8866:8866" -v log:/log -v pinger-node:/opt/node -it network-pinger
