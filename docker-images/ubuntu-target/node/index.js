var express = require('express');
var os = require('os');
var bodyParser = require('body-parser');
var winston = require('winston');

const updPort = 4000;
const httpPort=8888;
const dgram = require('dgram');
var attackCount = 0;
var udpCount = 0;
var app = express();
const milliseconds = 0.1 
var infoJSON = {};

winston.log('info', 'info logger');
winston.add(winston.transports.File, { filename: '/log/current/nodejs-target-' + os.hostname() + '.log' });
winston.remove(winston.transports.Console);

function delay(seconds){
	var delay = new Date().getTime() + (seconds * 1000);
	while (new Date().getTime() <= delay) {}
}

function doLog(obj) {
	console.log(obj); 
	winston.info(obj);
}

// Listen for emission of the UDP "message" event.
var server = dgram.createSocket('udp4');
server.on('message', function (message) {
	delay(milliseconds);
	udpCount++;
	doLog('udpCount: '+udpCount);
});
server.bind(updPort);
doLog('udp server started on port '+ updPort);

app.use( bodyParser.json() );						// to support JSON-encoded bodies
app.use( bodyParser.urlencoded({extended: true}) );	// to support URL-encoded bodies

/**
* HTTP attack url.
*/
app.post('/attackme', function (req, res) {
	delay(milliseconds);
	attackCount++;

	infoJSON[req.body.host] = {counter: req.body.counter}
	doLog(infoJSON); 

	res.send('thank you for attacking, please come again.');
});

/**
* Simple URL end point to count the number of connects made over HTTP and UDP.
*/
app.get('/attackcount', function (req, res) {
  res.send('attackme has been accessed ' + attackCount + ' times by HTTP<br/>Host has been accessed ' + udpCount + ' times by UDP<br/>' + JSON.stringify(infoJSON));
});

app.listen(httpPort, function () {
  doLog('http server started on port '+ httpPort);
});
