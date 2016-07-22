var request = require('request');
var random = require("random-js")();
var host = "http://localhost:8080"
var express = require('express');

const updPort = 4000;
const httpPort=8888; 
const dgram = require('dgram');
var pingerCount = 0;
var attackCount = 0;
var app = express();
const milliseconds = 0.1 


/**
* HTTP attack url.
*/
app.get('/attackme', function (req, res) {
	delay(milliseconds);
	attackCount++;
  	res.send('thank you for attacking, please come again.');
});

/**
* Simple URL end point to count the number of connects made over HTTP and UDP.
*/
app.get('/attackcount', function (req, res) {
  res.send(
  		'attackme has been accessed ' + attackCount + ' times <br/>'
  	);
});

/**
* Service provides simple states on number of requests made to NGINX server.
*/
app.get('/', function (req, res) {
  res.send(
  		'Pinger has made ' + pingerCount + ' requests to the server '+ host +'<br/>'
  	);
});

app.listen(httpPort, function () {
  console.log('http server started on port '+ httpPort);
  console.log('udp server started on port '+ updPort);

});

function httpRequest(callback){
	pingerCount++;
	request(host, function (error, response, body) {
	  if (error || response.statusCode != 200)
	  	console.log(error)

	  if(callback)
		callback();
	})
	
};

function delay(seconds){
	var delay = new Date().getTime() + (seconds * 1000);
	while (new Date().getTime() <= delay) {}
}

function queryNginx(){
    httpRequest(function () {
    	setTimeout (queryNginx, random.integer(1, 100)) //queue for next ping in the next predefined interval
    });
}

function main(){
	console.log("Starting nodejs ping processor.");
	console.log("Pinging: "+host);
	 queryNginx();
};

/**
* UDP server, sends attacks on any url.
*/
// Listen for emission of the "message" event.
var server = dgram.createSocket('udp4');

server.on('message', function (message) {
	delay(milliseconds);
    attackCount++;
});

server.bind(updPort);


//Start processes.
main();
