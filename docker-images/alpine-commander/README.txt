Issue the following commands to get this image up and running

docker build -t alpine-commander .

# run commander on the testnetwork
docker run --name network-commander --rm -t --network=testnetwork_default -v log:/log alpine-commander
