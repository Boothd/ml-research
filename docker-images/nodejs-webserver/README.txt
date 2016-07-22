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

	A service for performing simple attacks on, ie http requests exists. This service has been setup to test the connectivity of attack scripts. Anything that perform a http GET on the URL below will increment a count held within the apps memory. The service is available on:

		http://localhost:8888/attackme

	To check the count, another url is available which simple reports the number of times /attackme has been accessed.

		http://localhost:8888/attackcount
