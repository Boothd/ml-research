Issue the following commands to get this image up and running

docker build -t network-pinger .
docker run --name pinger --rm -p "8866:8866" -v node:/opt/node -it network-pinger
