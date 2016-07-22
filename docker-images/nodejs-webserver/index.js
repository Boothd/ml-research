var request = require('request');
var random = require("random-js")();
var host = "http://localhost:8080"
var express = require('express');
var app = express();
// var http = require('http');
const PORT=8888; 
var pingerCount = 0;
var attackCount = 0;

app.get('/attackme', function (req, res) {
	attackCount++;
  	res.send('thank you for attacking, please come again.');
});

app.get('/attackcount', function (req, res) {
  res.send(
  		'attackme has been accessed ' + attackCount + ' times <br/>'
  	);
});

app.get('/', function (req, res) {
  res.send(
  		'Pinger has made ' + pingerCount + ' requests to the server '+ host +'<br/>'
  	);
});

app.listen(PORT, function () {
  console.log('server started on port '+ PORT);
});

/*
Test
*/


// function handleRequest(request, response){
//     response.end('Pinger has made ' + i + ' requests to the server '+ host);
// }
// var server = http.createServer(handleRequest);
// server.listen(PORT, function(){
//     //Callback triggered when server is successfully listening. Hurray!
//     console.log("Server listening on: http://localhost:%s", PORT);
// });

function httpRequest(callback){
	pingerCount++;
	request(host, function (error, response, body) {
	  if (error || response.statusCode != 200)
	  	console.log(error)

	  if(callback)
		callback();
	})
	
};

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

main();
