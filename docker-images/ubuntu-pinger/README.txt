Issue the following commands to get this image up and running

docker build -t network-pinger .
docker run -p 8866:8866 --name pinger -it network-pinger
