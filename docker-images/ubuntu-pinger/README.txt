Issue the following commands to get this image up and running

docker build -t network-pinger .
docker run --name pinger --rm -p "8080:8080" -v node:/opt/node -it network-pinger
