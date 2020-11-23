/* jshint ignore:start */
importScripts('/bower_components/requirejs/require.js');

window = self;
localStorage = {
    setItem: function (k, v) { localStorage[k] = v; },
    getItem: function (k) { return localStorage[k]; }
};

self.tabs = {};

var postMsg = function (client, data) {
    client.port.postMessage(data);
};

var debug = function (msg) { console.log(msg); };
// debug = function () {};

var init = function (client, cb) {
    debug('SharedW INIT');
    require.config({
        waitSeconds: 600
    });

    require(['/api/config?cb=' + (+new Date()).toString(16)], function (ApiConfig) {
        if (ApiConfig.requireConf) { require.config(ApiConfig.requireConf); }
        require([
            '/common/requireconfig.js'
        ], function (RequireConfig) {
            require.config(RequireConfig());
            require([
                '/common/common-util.js',
                '/common/outer/worker-channel.js',
                '/common/outer/store-rpc.js'
            ], function (Util, Channel, SRpc) {
                debug('SharedW Required ressources loaded');
                var msgEv = Util.mkEvent();

                if (!self.Rpc) {
                    self.Rpc = SRpc();
                }
                var Rpc = self.Rpc;

                var postToClient = function (data) {
                    postMsg(client, data);
                };
                Channel.create(msgEv, postToClient, function (chan) {
                    debug('SharedW Channel created');

                    var clientId = client.id;
                    client.chan = chan;
                    Object.keys(Rpc.queries).forEach(function (q) {
                        if (q === 'CONNECT') { return; }
                        if (q === 'JOIN_PAD') { return; }
                        if (q === 'SEND_PAD_MSG') { return; }
                        chan.on(q, function (data, cb) {
                            try {
                                Rpc.queries[q](clientId, data, cb);
                            } catch (e) {
                                console.error('Error in webworker when executing query ' + q);
                                console.error(e);
                                console.log(data);
                            }
                            if (q === "DISCONNECT") {
                                console.log('Deleting existing store!');
                                client.close();
                                if (self.accountDeletion && self.accountDeletion === client.id) {
                                    delete self.Rpc;
                                    delete self.store;
                                }
                            }
                        });
                    });
                    chan.on('CONNECT', function (cfg, cb) {
                        debug('SharedW connecting to store...');
                        if (self.store) {
                            debug('Store already exists!');
                            if (cfg.driveEvents) {
                                Rpc._subscribeToDrive(clientId);
                            }
                            return void cb(self.store);
                        }

                        debug('Loading new async store');
                        // One-time initialization (init async-store)
                        cfg.query = function (cId, cmd, data, cb) {
                            cb = cb || function () {};
                            self.tabs[cId].chan.query(cmd, data, function (err, data2) {
                                if (err) { return void cb({error: err}); }
                                cb(data2);
                            });
                        };
                        cfg.broadcast = function (excludes, cmd, data, cb) {
                            cb = cb || function () {};
                            Object.keys(self.tabs).forEach(function (cId) {
                                if (excludes.indexOf(cId) !== -1) { return; }
                                self.tabs[cId].chan.query(cmd, data, function (err, data2) {
                                    if (err) { return void cb({error: err}); }
                                    cb(data2);
                                });
                            });
                        };
                        Rpc.queries['CONNECT'](clientId, cfg, function (data) {
                            if (cfg.driveEvents) {
                                Rpc._subscribeToDrive(clientId);
                            }
                            if (data && data.state === "ALREADY_INIT") {
                                self.store = data.returned;
                                return void cb(data.returned);
                            }
                            self.store = data;
                            cb(data);
                        });
                    });
                    chan.on('JOIN_PAD', function (data, cb) {
                        client.channelId = data.channel;
                        try {
                            Rpc.queries['JOIN_PAD'](clientId, data, cb);
                        } catch (e) {
                            console.error('Error in webworker when executing query JOIN_PAD');
                            console.error(e);
                            console.log(data);
                        }
                    });
                    chan.on('SEND_PAD_MSG', function (msg, cb) {
                        var data = {
                            msg: msg,
                            channel: client.channelId
                        };
                        try {
                            Rpc.queries['SEND_PAD_MSG'](clientId, data, cb);
                        } catch (e) {
                            console.error('Error in webworker when executing query SEND_PAD_MSG');
                            console.error(e);
                            console.log(data);
                        }
                    });
                    cb();
                }, true);

                client.msgEv = msgEv;

                client.close = function () {
                    Rpc._removeClient(client.id);
                };
            });
        });
    });
};

onconnect = function(e) {
    debug('New SharedWorker client');
    var port = e.ports[0];
    var cId = Number(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER))
    var client = self.tabs[cId] = {
        id: cId,
        port: port
    };

    port.onmessage = function (e) {
        if (e.data === "INIT") {
            if (client.init) { return; }
            client.init = true;
            init(client, function () {
                postMsg(client, 'SW_READY');
            });
        } else if (e.data === "CLOSE") {
            if (client && client.close) {
                console.log('leave');
                client.close();
            }
        } else if (client && client.msgEv) {
            client.msgEv.fire(e);
        }
    };
};

