var express = require('express');
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
winston.add(winston.transports.File, { filename: '/log/nodejs-target.log' });
winston.remove(winston.transports.Console);

function delay(seconds){
	var delay = new Date().getTime() + (seconds * 1000);
	while (new Date().getTime() <= delay) {}
}

// Listen for emission of the UDP "message" event.
var server = dgram.createSocket('udp4');
server.on('message', function (message) {
	delay(milliseconds);
	udpCount++;
	winston.log('udpCount: '+udpCount);
});
server.bind(updPort);

app.use( bodyParser.json() );       // to support JSON-encoded bodies
app.use(bodyParser.urlencoded({     // to support URL-encoded bodies
  extended: true
}));

/**
* HTTP attack url.
*/
app.get('/attackme', function (req, res) {
	delay(milliseconds);
	attackCount++;
  	res.send('thank you for attacking, please come again.');
});

app.post('/attackme', function (req, res) {
	delay(milliseconds);
	attackCount++;
	infoJSON[req.body.host] = {counter: req.body.counter}
	console.log(infoJSON); 
	winston.info(infoJSON);
	res.send('thank you for attacking, please come again.');
});
/**
* Simple URL end point to count the number of connects made over HTTP and UDP.
*/
app.get('/attackcount', function (req, res) {
  res.send('attackme has been accessed ' + attackCount + ' times by HTTP<br/>Host has been accessed ' + udpCount + ' times by UDP'
  	+ '<br/>'
  	+ JSON.stringify(infoJSON)
  		);
});

app.listen(httpPort, function () {
  console.log('http server started on port '+ httpPort);
  console.log('udp server started on port '+ updPort);
});

