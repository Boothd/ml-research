How to build and start
	> docker build -t nodejs-pinger .
	> docker run -p 8888:8888 -it --rm --name nodejs-server nodejs-pinger

	NOTE: use a -d flag to run the process in the background ie

	> docker run -p 8888:8888 -d -it --name nodejs-server nodejs-pinger

Stopping
	The image can then be stopped using the command:
	> docker stop nodejs-server

Web Server
	There is a webserver running which reports which server the app is pinging and how many requests is has made. The page is accessible on:

		http://localhost:8888