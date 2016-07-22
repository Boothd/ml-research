var request = require('request');
var random = require("random-js")();
var i = 0;
var host = "http://localhost:8080"

/*
Test
*/
var http = require('http');
const PORT=8888; 

function handleRequest(request, response){
    response.end('Pinger has made ' + i + ' requests to the server '+ host);
}
var server = http.createServer(handleRequest);
server.listen(PORT, function(){
    //Callback triggered when server is successfully listening. Hurray!
    console.log("Server listening on: http://localhost:%s", PORT);
});

function httpRequest(callback){
	//console.log(i++);
	i++;
	request(host, function (error, response, body) {
	  if (!error && response.statusCode == 200) {
	    //console.log(body) 
	  } else{
	  	//console.log(error)
	  }
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