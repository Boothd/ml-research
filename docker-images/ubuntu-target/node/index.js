var express = require('express');

const updPort = 4000;
const httpPort=8888;
const dgram = require('dgram');
var attackCount = 0;
var udpCount = 0;
var app = express();
const milliseconds = 0.1 

function delay(seconds){
	var delay = new Date().getTime() + (seconds * 1000);
	while (new Date().getTime() <= delay) {}
}

// Listen for emission of the UDP "message" event.
var server = dgram.createSocket('udp4');
server.on('message', function (message) {
	delay(milliseconds);
	udpCount++;
});
server.bind(updPort);

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
  res.send('attackme has been accessed ' + attackCount + ' times by HTTP<br/>Host has been accessed ' + udpCount + ' times by UDP');
});

app.listen(httpPort, function () {
  console.log('http server started on port '+ httpPort);
  console.log('udp server started on port '+ updPort);
});

