docker build -t nodejs-pinger .
docker run -p 8888:8888 -it --rm --name nodejs-server nodejs-pinger

NOTE: us a -d flag to run the process in the background ie

docker run -p 8888:8888 -d -it --name nodejs-server nodejs-pinger

The image can then be stopped using the command:
docker stop nodejs-server