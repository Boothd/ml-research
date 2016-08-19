var request = require('request');
var os = require('os');
var random = require("random-js")();
var express = require('express');

const listenPort=8866;
const httpPort=8888;
var url = "http://target:" + httpPort + "/attackme";
var pingerCount = 0;
var app = express();

/**
* Service provides simple states on number of requests made to target server.
*/
app.get('/', function (req, res) {
	res.send('Pinger has made ' + pingerCount + ' requests to the URL ' + url);
});

app.listen(listenPort, function () {
  console.log('http server started on port '+ listenPort);
});

function httpRequest(callback){
	pingerCount++;
	request(url, function (error, response, body) {
	  if(callback)
		callback();
	})
};

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
		});
	pingerCount++;
}

function queryTarget(){
	// httpRequest(function () {
	// 	setTimeout (queryTarget, random.integer(1, 100)) //queue for next ping in the next predefined interval
	// });
	httpPost(function () {
	 	setTimeout (queryTarget, random.integer(1, 100)) //queue for next ping in the next predefined interval
	});
}

function main(){
	console.log("Starting nodejs ping processor.");
	console.log("Pinging: " + url);
	queryTarget();
};


// Start pinger processes.
main();
