var geoip     = require('geoip-lite');
var readline  = require('readline');
var fs        = require('fs');
var stream    = require('stream');
var websocket = require('websocket').server;
var http      = require('http');

//
// localip is required on nat
//
var localip   = "82.212.175.9";
var localinfo = geoip.lookup(localip);
var delay     = 0;

//
// colors is on server-side because it's based on source ip
// i don't want to send ip informations to clients, well hash is made
// on server side
//
var colors = [
	'#F0FF60', '#FFC460', '#FF7D60',
	'#FF6081', '#FF60C0', '#FF60F7',
	'#B760FF', '#7E60FF', '#6077FF',
	'#60AFFF', '#60F2FF', '#60FFC4',
	'#60FF75', '#9CFF60', '#D7FF60',
];

//
// websocket
//
var clients = [];

var server = http.createServer(function(req, response) {
	response.writeHead(404);
	response.end();
	
}).listen(1441);

var websock = new websocket({
	httpServer: server,
	autoAcceptConnections: false
});

function valide(origin) {
	// check origin
	return true;
}

websock.on('request', function(request) {
	if(!valide(request.origin)) {
		request.reject();
		return;
	}
	
	try {
		var connection = request.accept('maptraffic', request.origin);
		
	} catch(err) {
		console.log("[-] websocket: error: " + err);
		return;
	}
	
	console.log('[+] websocket: client accepted: ' + request.remoteAddress);
	
	clients.push(connection);
	
	connection.on('close', function() {
		console.log('[+] websocket: client disconnected');
		for(var i = 0; i < clients.length; i++) {
			if(clients[i] == connection) {
				delete clients[i];
				clients.length--;
				return;
			}
		}
	});
});

//
// reading data from pcap pipe
//
function init() {
	var instream = fs.createReadStream('/tmp/analyzer-fifo');
	var outstream = new stream;
	outstream.readable = true;
	outstream.writable = true;

	// auto-reopen file on close
	instream.on('end', function() {
		init();
	});
	
	var rl = readline.createInterface({
		input: instream,
		output: outstream,
		terminal: false
	});
	
	rl.on('line', parsing);
}

var mapping = {};

function parsing(line) {
	// skipping if no clients
	if(clients.length == 0)
		return;
	
	// grabbing source and destination from pcap
	var addresses = line.split(' -> ');
	
	//
	// skipping flood
	//
	if(mapping[addresses[0]] != undefined && addresses[0].substring(0, 3) != '192') {
		if(mapping[addresses[0]].last > new Date().getTime() - 1000)
			return;
	}
	
	mapping[addresses[0]] = {last: new Date().getTime()};
	
	if(mapping[addresses[1]] != undefined && addresses[1].substring(0, 3) != '192') {
		if(mapping[addresses[1]].last > new Date().getTime() - 1000)
			return;	
	}
	
	mapping[addresses[1]] = {last: new Date().getTime()};
	
	//
	// checking if public or local traffic
	//
	
	if(addresses[0].substring(0, 7) == '192.168' || addresses[0].substring(0, 7) == '172.16.')
		var source = localinfo;
	
	else var source = geoip.lookup(addresses[0]);
	
	if(addresses[1].substring(0, 7) == '192.168' || addresses[1].substring(0, 7) == '172.16.')
		var destination = localinfo;
	
	else var destination = geoip.lookup(addresses[1]);
	
	console.log(source);
	console.log(destination);
	
	if(!source || !destination)
		return;
	
	// choosing color
	var ip    = parseInt(addresses[0].replace(/\./g, ''));
	var color = colors[ip % colors.length];
	
	//
	// sending data to clients
	//
	for(var i = 0; i < clients.length; i++) {
		if(!clients[i])
			continue;
			
		clients[i].sendUTF(JSON.stringify({
			src: source.ll,
			dst: destination.ll,
			color: source.range[0],
			coloring: color
		}));
	}
}

init();
