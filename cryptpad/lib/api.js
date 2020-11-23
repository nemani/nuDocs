/* jshint esversion: 6 */
const WebSocketServer = require('ws').Server;
const NetfluxSrv = require('chainpad-server');
const Decrees = require("./decrees");

const nThen = require("nthen");

module.exports.create = function (Env) {
    var log = Env.Log;

nThen(function (w) {
    Decrees.load(Env, w(function (err) {
        if (err) {
            log.error('DECREES_LOADING', {
                error: err.code || err,
                message: err.message,
            });
            console.error(err);
        }
    }));
}).nThen(function () {
    // asynchronously create a historyKeeper and RPC together
    require('./historyKeeper.js').create(Env, function (err, historyKeeper) {
        if (err) { throw err; }


        var noop = function () {};

        var special_errors = {};
        ['EPIPE', 'ECONNRESET'].forEach(function (k) { special_errors[k] = noop; });
        special_errors.NF_ENOENT = function (error, label, info) {
            delete info.stack;
            log.error(label, {
                info: info,
            });
        };

        // spawn ws server and attach netflux event handlers
        NetfluxSrv.create(new WebSocketServer({ server: Env.httpServer}))
            .on('channelClose', historyKeeper.channelClose)
            .on('channelMessage', historyKeeper.channelMessage)
            .on('channelOpen', historyKeeper.channelOpen)
            .on('sessionClose', historyKeeper.sessionClose)
            .on('error', function (error, label, info) {
                if (!error) { return; }
                var code = error && (error.code || error.message);
                if (code) {
                    /*  EPIPE,ECONNERESET, NF_ENOENT */
                    if (typeof(special_errors[code]) === 'function') {
                        return void special_errors[code](error, label, info);
                    }
                }

                /* labels:
                    SEND_MESSAGE_FAIL, SEND_MESSAGE_FAIL_2, FAIL_TO_DISCONNECT,
                    FAIL_TO_TERMINATE, HANDLE_CHANNEL_LEAVE, NETFLUX_BAD_MESSAGE,
                    NETFLUX_WEBSOCKET_ERROR
                */
                log.error(label, {
                    code: error.code,
                    message: error.message,
                    stack: error.stack,
                    info: info,
                });
            })
            .register(historyKeeper.id, historyKeeper.directMessage);
    });
});

};
