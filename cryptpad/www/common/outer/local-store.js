define([
    '/common/common-constants.js',
    '/common/common-hash.js',
    '/bower_components/localforage/dist/localforage.min.js',
    '/customize/application_config.js',
], function (Constants, Hash, localForage, AppConfig) {
    var LocalStore = {};

    LocalStore.setThumbnail = function (key, value, cb) {
        localForage.setItem(key, value, cb);
    };
    LocalStore.getThumbnail = function (key, cb) {
        localForage.getItem(key, cb);
    };
    LocalStore.clearThumbnail = function (cb) {
        cb = cb || function () {};
        localForage.clear(cb);
    };

    LocalStore.setFSHash = function (hash) {
        var sHash = Hash.serializeHash(hash);
        localStorage[Constants.fileHashKey] = sHash;
    };
    LocalStore.getFSHash = function () {
        var hash = localStorage[Constants.fileHashKey];

        if (['undefined', 'undefined/'].indexOf(hash) !== -1) {
            localStorage.removeItem(Constants.fileHashKey);
            return;
        }

        if (hash) {
            var sHash = Hash.serializeHash(hash);
            if (sHash !== hash) { localStorage[Constants.fileHashKey] = sHash; }
        }

        return hash;
    };

    var getUserHash = LocalStore.getUserHash = function () {
        var hash = localStorage[Constants.userHashKey];

        if (['undefined', 'undefined/'].indexOf(hash) !== -1) {
            localStorage.removeItem(Constants.userHashKey);
            return;
        }

        if (hash) {
            var sHash = Hash.serializeHash(hash);
            if (sHash !== hash) { localStorage[Constants.userHashKey] = sHash; }
        }

        return hash;
    };

    LocalStore.setUserHash = function (hash) {
        var sHash = Hash.serializeHash(hash);
        localStorage[Constants.userHashKey] = sHash;
    };

    LocalStore.getBlockHash = function () {
        return localStorage[Constants.blockHashKey];
    };

    LocalStore.setBlockHash = function (hash) {
        localStorage[Constants.blockHashKey] = hash;
    };

    LocalStore.getAccountName = function () {
        return localStorage[Constants.userNameKey];
    };

    LocalStore.isLoggedIn = function () {
        return typeof getUserHash() === "string";
    };

    LocalStore.login = function (hash, name, cb) {
        if (!hash) { throw new Error('expected a user hash'); }
        if (!name) { throw new Error('expected a user name'); }
        hash = Hash.serializeHash(hash);
        localStorage.setItem(Constants.userHashKey, hash);
        localStorage.setItem(Constants.userNameKey, name);
        if (cb) { cb(); }
    };
    var logoutHandlers = [];
    LocalStore.logout = function (cb, isDeletion) {
        [
            Constants.userNameKey,
            Constants.userHashKey,
            Constants.blockHashKey,
            'loginToken',
            'plan',
        ].forEach(function (k) {
            localStorage.removeItem(k);
            delete localStorage[k];
        });
        sessionStorage.clear();
        try {
            Object.keys(localStorage || {}).forEach(function (k) {
                // Remvoe everything in localStorage except CACHE and FS_hash
                if (/^CRYPTPAD_CACHE/.test(k) || /^LESS_CACHE/.test(k) || k === Constants.fileHashKey) { return; }
                delete localStorage[k];
            });
        } catch (e) { console.error(e); }
        LocalStore.clearThumbnail();
        // Make sure we have an FS_hash in localStorage before reloading all the tabs
        // so that we don't end up with tabs using different anon hashes
        if (!LocalStore.getFSHash()) {
            LocalStore.setFSHash(Hash.createRandomHash('drive'));
        }

        if (!isDeletion) {
            logoutHandlers.forEach(function (h) {
                if (typeof (h) === "function") { h(); }
            });
        }

        if (typeof(AppConfig.customizeLogout) === 'function') {
            return void AppConfig.customizeLogout(cb);
        }

        if (cb) { cb(); }
    };
    var loginHandlers = [];
    LocalStore.loginReload = function () {
        loginHandlers.forEach(function (h) {
            if (typeof (h) === "function") { h(); }
        });
        document.location.reload();
    };
    LocalStore.onLogin = function (h) {
        if (typeof (h) !== "function") { return; }
        if (loginHandlers.indexOf(h) !== -1) { return; }
        loginHandlers.push(h);
    };
    LocalStore.onLogout = function (h) {
        if (typeof (h) !== "function") { return; }
        if (logoutHandlers.indexOf(h) !== -1) { return; }
        logoutHandlers.push(h);
    };



    return LocalStore;
});
