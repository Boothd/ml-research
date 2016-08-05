Issue the following commands to get this image up and running on http://localhost:8080

> docker build -t simple-nginx .
> docker run --name nginx-server -d -p 8080:80 simple-nginx