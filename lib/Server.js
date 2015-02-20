/**
 * Copyright (C) 2015 Joe Bandenburg
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

var querystring = require("querystring");
var crypto = require("crypto");
var express = require("express");
var cors = require("cors");
var bodyParser = require("body-parser");
var WebSocketServer = require("ws").Server;

var webSocketProtos = require("./WebSocketProtos");
var incomingPushMessageSignalProtos = require("./IncomingPushMessageSignalProtos");

var IncomingPushMessageSignal = incomingPushMessageSignalProtos.IncomingPushMessageSignal;
var WebSocketMessage = webSocketProtos.WebSocketMessage;

var unpackNumberDeviceString = function(numberString) {
    var numberAndDevice = numberString.split(".", 2);
    return {
        number: numberAndDevice[0],
        deviceId: numberAndDevice[1]
    };
};

var packNumberDevice = function(number, deviceId) {
    return number + "." + deviceId;
};

var parseAuth = function(req) {
    var auth = req.get("Authorization");
    var authString = new Buffer(auth.substring(6), "base64").toString("ascii");
    var authParts = authString.split(":", 2);
    var numberDevice = unpackNumberDeviceString(authParts[0]);
    return {
        number: numberDevice.number,
        deviceId: numberDevice.deviceId,
        password: authParts[1]
    };
};

function Contact() {
    this.devices = {};
}

function Server(contactStore, port) {
    var app = express();

    app.use(cors());
    app.use(bodyParser.json());

    app.get("/v1/accounts/:transport/code/:number", function(req, res) {
        contactStore.putContact(req.params.number, new Contact()).then(function() {
            res.status(200).end();
        });
    });

    app.put("/v1/accounts/code/:code", function(req, res) {
        var auth = parseAuth(req);
        contactStore.getContact(auth.number).then(function(contact) {
            var signalingKeyBytes = new Buffer(req.body.signalingKey, "base64");
            contact.devices[1] = {
                password: auth.password,
                signalingKey: {
                    cipherKey: signalingKeyBytes.slice(0, 32),
                    macKey: signalingKeyBytes.slice(32)
                },
                registrationId: req.body.registrationId
            };
            return contactStore.putContact(auth.number, contact);
        }).then(function() {
            res.status(200).end();
        });
    });

    app.put("/v2/keys", function(req, res) {
        var auth = parseAuth(req);
        contactStore.getContact(auth.number).then(function(contact) {
            var device = contact.devices[auth.deviceId];
            device.lastResortKey = req.body.lastResortKey;
            device.preKeys = req.body.preKeys.map(function(preKey) {
                if (typeof preKey.keyId === "string") {
                    preKey.keyId = parseInt(preKey.keyId, 10);
                }
                return preKey;
            });
            device.signedPreKey = req.body.signedPreKey;
            contact.identityKey = req.body.identityKey;
            return contactStore.putContact(auth.number, contact);
        }).then(function() {
            res.status(200).end();
        });
    });

    app.get("/v2/keys/:number/:device", function(req, res) {
        contactStore.getContact(req.params.number).then(function(otherContact) {
            if (!otherContact) {
                res.status(404).end();
            } else {
                var deviceIds = [];
                if (req.params.device === "*") {
                    deviceIds = Object.keys(otherContact.devices);
                } else if (otherContact.devices[req.params.device]) {
                    deviceIds = [req.params.device];
                }
                if (deviceIds.length === 0) {
                    res.status(404).end();
                } else {
                    var response = {
                        identityKey: otherContact.identityKey,
                        devices: deviceIds.map(function(deviceId) {
                            var device = otherContact.devices[deviceId];
                            var preKey = device.preKeys.shift();
                            return {
                                signedPreKey: device.signedPreKey,
                                preKey: preKey,
                                registrationId: device.registrationId,
                                deviceId: deviceId
                            };
                        })
                    };
                    return contactStore.putContact(req.params.number, otherContact).then(function() {
                        res.status(200).send(response);
                    });
                }
            }
        });
    });

    app.put("/v1/messages/:number", function(req, res) {
        var auth = parseAuth(req);
        contactStore.getContact(req.params.number).then(function(toContact) {
            if (!toContact) {
                res.status(404).end();
                return;
            }
            var missingDevices = Object.keys(toContact.devices).map(function(id) {
                return parseInt(id, 10);
            });
            var staleDevices = [];
            var extraDevices = [];
            req.body.messages.forEach(function(message) {
                var device = toContact.devices[message.destinationDeviceId];
                if (!device) {
                    extraDevices.push(message.destinationDeviceId);
                } else if (message.destinationRegistrationId !== undefined &&
                    message.destinationRegistrationId !== device.registrationId) {
                    staleDevices.push(message.destinationDeviceId);
                } else {
                    missingDevices.splice(missingDevices.indexOf(message.destinationDeviceId), 1);
                }
            });
            if (staleDevices.length > 0) {
                res.status(410).send({
                    staleDevices: staleDevices
                });
            } else if (missingDevices.length > 0 || extraDevices.length > 0) {
                res.status(409).send({
                    missingDevices: missingDevices,
                    extraDevices: extraDevices
                });
            } else {
                req.body.messages.forEach(function(message) {
                    var incomingPushMessageSignalBytes = new IncomingPushMessageSignal({
                        type: message.type,
                        source: auth.number,
                        sourceDevice: parseInt(auth.deviceId, 10),
                        timestamp: message.timestamp,
                        message: new Buffer(message.body, "base64")
                    }).encode().toBuffer();

                    var device = toContact.devices[message.destinationDeviceId];
                    var finalMessage = encryptMessageForDevice(incomingPushMessageSignalBytes, device);

                    var connectionId = packNumberDevice(req.params.number, message.destinationDeviceId);
                    var connection = webSocketConnections[connectionId];
                    if (connection) {
                        sendWebSocketRequest(connection, "PUT", "/api/v1/message", finalMessage, function() {
                            sendDeliveryReceipt(auth.number, req.params.number, message.destinationDeviceId,
                                message.timestamp);
                        });
                    }
                });
                res.status(200).end();
            }
        });
    });

    var encryptMessageForDevice = function(incomingPushMessageSignalBytes, device) {
        var iv = crypto.randomBytes(16);
        var cipher = crypto.createCipheriv("aes-256-cbc", new Buffer(device.signalingKey.cipherKey), iv);
        var buffer1 = cipher.update(incomingPushMessageSignalBytes);
        var buffer2 = cipher.final();
        var encryptedIncomingPushMessageSignalBytes = Buffer.concat([buffer1, buffer2]);

        var versionByte = new Buffer([1]);
        var macingBytes = Buffer.concat([versionByte, iv, encryptedIncomingPushMessageSignalBytes]);

        var hmac = crypto.createHmac("sha256", new Buffer(device.signalingKey.macKey));
        hmac.update(macingBytes);
        var mac = hmac.digest().slice(0, 10);

        return Buffer.concat([versionByte, iv, encryptedIncomingPushMessageSignalBytes, mac]);
    };

    var sendDeliveryReceipt = function(destNumber, sourceNumber, sourceDeviceId, timestamp) {
        var incomingPushMessageSignalBytes = new IncomingPushMessageSignal({
            type: IncomingPushMessageSignal.Type.RECEIPT,
            source: sourceNumber,
            sourceDevice: sourceDeviceId,
            timestamp: timestamp
        }).encode().toBuffer();
        contactStore.getContact(destNumber).then(function(contact) {
            Object.keys(contact.devices).forEach(function(deviceId) {
                var device = contact.devices[deviceId];
                var finalMessage = encryptMessageForDevice(incomingPushMessageSignalBytes, device);
                var connectionId = packNumberDevice(destNumber, deviceId);
                var connection = webSocketConnections[connectionId];
                if (connection) {
                    sendWebSocketRequest(connection, "PUT", "/api/v1/message", finalMessage);
                }
            });
        });
    };

    var sendWebSocketRequest = function(connection, verb, path, body, callback) {
        var id = crypto.randomBytes(4).readUInt32LE(0);
        connection.pendingRequestMap[id] = callback;
        var webSocketMessageBytes = new WebSocketMessage({
            type: WebSocketMessage.Type.REQUEST,
            request: {
                verb: verb,
                path: path,
                body: body,
                id: id
            }
        }).encode().toBuffer();
        connection.send(webSocketMessageBytes);
    };

    var webSocketConnections = {};

    var server = app.listen(port);

    var wss = new WebSocketServer({
        server: server,
        path: "/v1/websocket/",
        verifyClient: function(info, callback) {
            var query = querystring.parse(info.req.url.split("?", 2)[1]);
            if (!query.login) {
                return false;
            }
            query.login = unpackNumberDeviceString(query.login);
            contactStore.getContact(query.login.number).then(function(contact) {
                if (!contact) {
                    return false;
                }
                var device = contact.devices[query.login.deviceId];
                if (!device) {
                    return false;
                }
                return device.password === query.password;
            }).then(callback);
        }
    });
    wss.on("connection", function(ws) {
        var query = querystring.parse(ws.upgradeReq.url.split("?", 2)[1]);
        webSocketConnections[query.login] = ws;
        ws.pendingRequestMap = {};
        ws.on("close", function() {
            delete webSocketConnections[query.login];
        });
        ws.on("message", function(data) {
            var message = WebSocketMessage.decode(data);
            if (message.type === WebSocketMessage.Type.RESPONSE) {
                var response = message.response;
                var pendingRequest = ws.pendingRequestMap[response.id];
                if (pendingRequest) {
                    pendingRequest(response.status);
                    delete ws.pendingRequestMap[response.id];
                }
            }
        });
    });

    this.close = server.close.bind(server);
}

module.exports = Server;
