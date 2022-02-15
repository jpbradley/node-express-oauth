const fs = require("fs")
const express = require("express")
const bodyParser = require("body-parser")
const jwt = require("jsonwebtoken")
const {
	randomString,
	containsAll,
	decodeAuthCredentials,
	timeout,
} = require("./utils")
const restoreObject = require("sinon/lib/sinon/restore-object")

const config = {
	port: 9001,
	privateKey: fs.readFileSync("assets/private_key.pem"),

	clientId: "my-client",
	clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
	redirectUri: "http://localhost:9000/callback",

	authorizationEndpoint: "http://localhost:9001/authorize",
}

const clients = {
	"my-client": {
		name: "Sample Client",
		clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
		scopes: ["permission:name", "permission:date_of_birth"],
	},
	"test-client": {
		name: "Test Client",
		clientSecret: "TestSecret",
		scopes: ["permission:name"],
	},
}

const users = {
	user1: "password1",
	john: "appleseed",
}

const requests = {}
const authorizationCodes = {}

let state = ""

const app = express()
app.set("view engine", "ejs")
app.set("views", "assets/authorization-server")
app.use(timeout)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

/*
Your code here
*/
app.get('/authorize', function(req, res){
	const client_id = req.query.client_id
	const client = clients[client_id]

	if (!client) {
		res.status(401).send("Invalid client")
		return
	}

	if (!containsAll(client.scopes, req.query.scope.split(" "))) {
		res.status(401).send("Invalid scoping")
		return
	}

	const request_key = randomString()
	requests[request_key] = req.query

	res.render("login", { client: client, scope: req.query.scope, requestId: request_key })
})

app.post('/approve', function(req, res){
	const username =   req.body.userName
	const password =   req.body.password
	const request_id = req.body.requestId

	if (!users[username]) {
		res.status(401).send()
		return
	}

	if (users[username] !== password) {
		res.status(401).send()
		return
	}

	if (!requests[request_id]) {
		res.status(401).send()
		return
	}

	const request = requests[request_id]
	delete requests[request_id]

	const key = randomString()
	authorizationCodes[key] = { clientReq: request, userName: username }

	const url = new URL(request.redirect_uri)
	url.searchParams.set('code', key)
	url.searchParams.set('state', request.state)
	
	res.redirect(url)
})

const server = app.listen(config.port, "localhost", function () {
	var host = server.address().address
	var port = server.address().port
})

// for testing purposes

module.exports = { app, requests, authorizationCodes, server }
