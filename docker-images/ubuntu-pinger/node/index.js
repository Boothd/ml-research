var request = require('request');
var os = require('os');
var random = require("random-js")();
var express = require('express');
var winston = require('winston');

const listenPort=8866;
const httpPort=8888;
var url = "http://target:" + httpPort + "/attackme";
var pingerCount = 0;
var app = express();
var infoJSON = {};

winston.log('info', 'info logger');
winston.add(winston.transports.File, { filename: '/log/current/nodejs-pinger-' + os.hostname() + '.log' });
winston.remove(winston.transports.Console);

/**
* Service provides simple states on number of requests made to target server.
*/
app.get('/', function (req, res) {
	res.send('Pinger has made ' + pingerCount + ' requests to the URL ' + url);
});

app.listen(listenPort, function () {
  console.log('http server started on port '+ listenPort);
});

function httpPost(callback){
	request({
			method: 'POST',
			json: true,
			headers: {'content-type' : 'application/json'},
  			url:     url,
  			body:    {counter: pingerCount, host: os.hostname()}
		},
		function(error, response, body){
			if(callback)
				callback();
		}
	);
	pingerCount++;
	
	infoJSON[url] = {counter: pingerCount}
	console.log(infoJSON); 
	winston.info(infoJSON);
}

function queryTarget(){
	httpPost(function () {
	 	setTimeout (queryTarget, random.integer(1, 10000)) //queue for next ping in the next predefined interval
	});
}

function main(){
	console.log("Starting nodejs ping processor.");
	console.log("Pinging: " + url);
	queryTarget();
};

// Start pinger processes.
main();
