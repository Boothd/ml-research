var request = require('request');
var random = require("random-js")();
var express = require('express');

const httpPort=8866;

var host = "http://target:" + httpPort;
var pingerCount = 0;
var app = express();

/**
* Service provides simple states on number of requests made to target server.
*/
app.get('/', function (req, res) {
	res.send('Pinger has made ' + pingerCount + ' requests to the server ' + host);
});

app.listen(httpPort, function () {
  console.log('http server started on port '+ httpPort);
});

function httpRequest(callback){
	pingerCount++;
	request(host, function (error, response, body) {
	  if(callback)
		callback();
	})
};

function delay(seconds){
	var delay = new Date().getTime() + (seconds * 1000);
	while (new Date().getTime() <= delay) {}
}

function queryTarget(){
	httpRequest(function () {
		setTimeout (queryTarget, random.integer(1, 100)) //queue for next ping in the next predefined interval
	});
}

function main(){
	console.log("Starting nodejs ping processor.");
	console.log("Pinging: " + host);
	queryTarget();
};


// Start pinger processes.
main();
