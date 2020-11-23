define([
    '/bower_components/chainpad-crypto/crypto.js',
    '/bower_components/chainpad-netflux/chainpad-netflux.js',
    '/bower_components/netflux-websocket/netflux-client.js',
    '/common/common-util.js',
    '/common/common-hash.js',
    '/common/common-realtime.js',
    '/common/outer/network-config.js',
    '/common/pinpad.js',
    '/bower_components/nthen/index.js',
    '/bower_components/chainpad/chainpad.dist.js',
], function (Crypto, CPNetflux, Netflux, Util, Hash, Realtime, NetConfig, Pinpad, nThen) {
    var finish = function (S, err, doc) {
        if (S.done) { return; }
        S.cb(err, doc);
        S.done = true;

        if (!S.hasNetwork) {
            var disconnect = Util.find(S, ['network', 'disconnect']);
            if (typeof(disconnect) === 'function') { disconnect(); }
        }
        if (S.realtime && S.realtime.stop) {
            try {
                S.realtime.stop();
            } catch (e) { console.error(e); }
        }
        var abort = Util.find(S, ['session', 'realtime', 'abort']);
        if (typeof(abort) === 'function') {
            S.session.realtime.sync();
            abort();
        }
    };

    var makeNetwork = function (cb) {
        var wsUrl = NetConfig.getWebsocketURL();
        Netflux.connect(wsUrl).then(function (network) {
            cb(null, network);
        }, function (err) {
            cb(err);
        });
    };

    var start = function (Session, config) {
        // Create a network and authenticate with all our keys if necessary,
        // then start chainpad-netflux
        nThen(function (waitFor) {
            if (Session.hasNetwork) { return; }
            makeNetwork(waitFor(function (err, network) {
                if (err) { return; }
                config.network = network;
            }));
        }).nThen(function () {
            Session.realtime = CPNetflux.start(config);
        });
    };

    var onRejected = function (config, Session, data, cb) {
        // Check if we can authenticate
        if (!Array.isArray(data) || !data.length || data[0].length !== 16) {
            return void cb(true);
        }
        if (!Array.isArray(Session.accessKeys)) { return void cb(true); }

        // Authenticate
        config.network.historyKeeper = data[0];
        nThen(function (waitFor) {
            Session.accessKeys.forEach(function (obj) {
                Pinpad.create(config.network, obj, waitFor(function (e) {
                    console.log('done', obj);
                    if (e) { console.error(e); }
                }));
            });
        }).nThen(function () {
            cb();
        });
    };

    var makeConfig = function (hash, opt) {
        var secret;
        if (typeof(hash) === 'string') {
        // We can't use cryptget with a file or a user so we can use 'pad' as hash type
            secret = Hash.getSecrets('pad', hash, opt.password);
        } else if (typeof(hash) === 'object') {
            // we may want to just supply options directly
            // and this is the easiest place to do it
            secret = hash;
        }
        if (!secret.keys) { secret.keys = secret.key; } // support old hashses
        var config = {
            websocketURL: NetConfig.getWebsocketURL(opt.origin),
            channel: secret.channel,
            validateKey: secret.keys.validateKey || undefined,
            crypto: Crypto.createEncryptor(secret.keys),
            logLevel: 0,
            initialState: opt.initialState
        };
        return config;
    };

    var isObject = function (o) {
        return typeof(o) === 'object';
    };

    var overwrite = function (a, b) {
        if (!(isObject(a) && isObject(b))) { return; }
        Object.keys(b).forEach(function (k) { a[k] = b[k]; });
    };

    var get = function (hash, cb, opt, progress) {
        if (typeof(cb) !== 'function') {
            throw new Error('Cryptget expects a callback');
        }
        opt = opt || {};
        progress = progress || function () {};

        var config = makeConfig(hash, opt);
        var Session = {
            cb: cb,
            accessKeys: opt.accessKeys,
            hasNetwork: Boolean(opt.network)
        };

        config.onRejected = function (data, cb) {
            onRejected(config, Session, data, cb);
        };

        config.onReady = function (info) {
            var rt = Session.session = info.realtime;
            Session.network = info.network;
            progress(1);
            finish(Session, void 0, rt.getUserDoc());
        };

        config.onError = function (info) {
            finish(Session, info.error);
        };
        config.onChannelError = function (info) {
            finish(Session, info.error);
        };

        // We use the new onMessage handler to compute the progress:
        // we should receive 2 checkpoints max, so 100 messages max
        // We're going to consider that 1 message = 1%, and we'll send 100%
        // at the end
        var i = 0;
        config.onMessage = function () {
            i++;
            progress(Math.min(0.99, i/100));
        };

        overwrite(config, opt);

        start(Session, config);
    };

    var put = function (hash, doc, cb, opt) {
        if (typeof(cb) !== 'function') {
            throw new Error('Cryptput expects a callback');
        }
        opt = opt || {};

        var config = makeConfig(hash, opt);
        var Session = {
            cb: cb,
            accessKeys: opt.accessKeys,
            hasNetwork: Boolean(opt.network)
        };

        config.onRejected = function (data, cb) {
            onRejected(config, Session, data, cb);
        };

        config.onReady = function (info) {
            var realtime = Session.session = info.realtime;
            Session.network = info.network;

            realtime.contentUpdate(doc);

            var to = setTimeout(function () {
                cb(new Error("Timeout"));
            }, 15000);

            Realtime.whenRealtimeSyncs(realtime, function () {
                clearTimeout(to);
                var doc = realtime.getAuthDoc();
                realtime.abort();
                finish(Session, void 0, doc);
            });
        };
        overwrite(config, opt);

        start(Session, config);
    };

    return {
        get: get,
        put: put,
    };
});
