'use strict';
const net      = require('net');
const punycode = require('punycode');

/**
 * Whois servers
 * @const {object}
 */
const SERVERS = require('./servers.json');

/**
 * Default connection options for whois server
 * @const {object}
 */
const DEFAULT_WHOIS_OPTIONS = {
    PORT : 43,
    QUERY: '$host\r\n'
};

/**
 * Default options
 * @const {object}
 */
const DEFAULT_OPTIONS = {
    follow: 2,
    server: null
};

/**
 * Error messages
 * @const {object}
 */
const ERR = {
    EMAIL_NOT_SUPPORTED: 'lookup: email hostesses not supported',
    NO_WHOIS_SERVER    : 'lookup: no whois server is known for this kind of object',
    TIMEOUT            : 'lookup: timeout'
};


const lookup = (host, options = {}) => {
    return new Promise((resolve, reject) => {
        host    = host.trim().toLowerCase();
        options = Object.assign({}, DEFAULT_OPTIONS);

        // define whois server if it wasn't defined in options manualy
        if (options.server === null) {
            // host is email address so reject
            if (host.includes('@'))
                return reject(new Error(ERR.EMAIL_NOT_SUPPORTED));

            // host is IP
            else if (net.isIP(host) !== 0)
                options.server = SERVERS['_']['ip'];

            // host is probably domain name
            else {
                // try to find whois server for domain name by its TLD
                let tld = punycode.toASCII(host);
                while (options.server === null && tld.length > 0) {
                    if (tld in SERVERS)
                        options.server = SERVERS[tld];
                    else
                        tld = tld.split('.').slice(1).join('.');
                }
            }
        }

        if (options.server === null)
            return reject(new Error(ERR.NO_WHOIS_SERVER));

        if (typeof options.server === 'string') {
            const [whois_host, port] = options.server.split(':');
            options.server = {host: whois_host, port};
        }

        if (typeof options.server.port === 'undefined')
            options.server.port = DEFAULT_WHOIS_OPTIONS.PORT;

        if (typeof options.server.query === 'undefined')
            options.server.query = DEFAULT_WHOIS_OPTIONS.QUERY;

        const conn_options = {
            host: options.server.host,
            port: options.server.port
        };
        const socket = net.connect(conn_options);

        socket.setEncoding('utf-8');

        if ('timeout' in options)
            socket.setTimeout(options.timeout);

        // perform request
        socket.on('connect', () => {
            // handle IDN
            let idn;
            if (('punycode' in options.server && !options.server.punycode) ||
                ('punycode' in options        && !options.punycode))
                idn = host;
            else
                idn = punycode.toASCII(host);

            socket.write(options.server.query.replace('$addr', idn));
        });

        // read from socket
        let buf = '';
        socket.on('data', chunk => buf += chunk);

        socket.on('timeout', () => {
            socket.destroy();
            return reject(new Error(ERR.TIMEOUT));
        });

        socket.on('error', err => reject(err));

        socket.on('close', err => {
            if (err !== null)
                return reject(err);

            // follow whois server from answer if there is one
            if (options.follow > 0) {
                const match = buf.match(/(ReferralServer|Registrar Whois|Whois Server):\s*(r?whois:\/\/)?(.+)/);
                if (match !== null) {
                    options = Object.assign({}, options, {
                        follow: options.follow - 1,
                        server: match[3]
                    });

                    lookup(host, options)
                    .then(data => {
                        resolve(
                            buf.trim().concat('\n\n', data.trim())
                        );
                    })
                    .catch(err => reject(err));
                }
            } else
                resolve(buf.trim());
        });
    });
};


exports.lookup = lookup;
