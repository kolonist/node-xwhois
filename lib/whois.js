'use strict';
const dns        = require('dns').promises;
const net        = require('net');
const https      = require('https');
const fs         = require('fs');
const zlib       = require('zlib');
const jszip      = require('jszip');
const tar        = require('tar-stream');
const punycode   = require('punycode');
const path       = require('path');
const ip2loc     = require('ip2location-nodejs');
const ip2proxy   = require('ip2proxy-nodejs');
const mmdbReader = require('@maxmind/geoip2-node').Reader;
const node_whois = require('whois');


// GeoIP info object
let maxMind     = null;
let maxMind_asn = null;

// show whether geoIP was initialized or not
let geoInitialized = false;


/**
 * A JavaScript equivalent of PHP's ip2long(). Convert IPv4 address in dotted
 * notation to 32-bit long integer.
 * You can pass IP in all possible representations, i.e.:
 *     192.0.34.166
 *     0xC0.0x00.0x02.0xEB
 *     0xC00002EB
 *     3221226219
 *     0.0xABCDEF
 *     255.255.255.256
 *     0300.0000.0002.0353
 *     030000001353
 *
 * @param {string} ip IPv4-address in one of possible representations.
 * @return {number} The 32-bit number notation of IP-address expressed in
 *                  decimal.
 */
const ip2long = ip => {
    // discuss at: http://phpjs.org/functions/ip2long/
    // original by: Waldo Malqui Silva
    // improved by: Victor
    // improved by: Alexander Zubakov

    // PHP allows decimal, octal, and hexadecimal IP components.
    // PHP allows between 1 (e.g. 127) to 4 (e.g 127.0.0.1) components.
    ip = ip.match(
        /^([1-9]\d*|0[0-7]*|0x[\da-f]+)(?:\.([1-9]\d*|0[0-7]*|0x[\da-f]+))?(?:\.([1-9]\d*|0[0-7]*|0x[\da-f]+))?(?:\.([1-9]\d*|0[0-7]*|0x[\da-f]+))?$/i
    );

    // invalid format.
    if (ip === null) return false;

    // reuse IP variable for component counter.
    ip[0] = 0;
    for (let i = 1; i <= 4; i++) {
        // calculate radix for parseInt()
        let radix = 10;

        // radix should be 8 or 16
        if (typeof ip[i] !== 'undefined' && ip[i].length > 1 && ip[i][0] === '0')
            radix = ip[i][1].toLowerCase() === 'x' ? 16 : 8;

        ip[0] += !! ((ip[i] || '').length);
        ip[i] = parseInt(ip[i], radix) || 0;
    }

    // continue to use IP for overflow values.
    // PHP does not allow any component to overflow.
    ip.push(256, 256, 256, 256);

    // recalculate overflow of last component supplied to make up for missing components.
    ip[4 + ip[0]] *= Math.pow(256, 4 - ip[0]);

    if (ip[1] >= ip[5] || ip[2] >= ip[6] || ip[3] >= ip[7] || ip[4] >= ip[8])
        return false;

    return ip[1] * (ip[0] === 1 || 16777216) + ip[2] * (ip[0] <= 2 || 65536) + ip[3] * (ip[0] <= 3 || 256) + ip[4] * 1;
};


/**
 * Detect if host is correct IP-address.
 *
 * @param {string} host String to test.
 * @return {boolean} True if host is correct IP-address or false otherwise.
 */
const isIP = host => net.isIP(host) !== 0;


/**
 * Detect if host is correct domain name. It can't test IDN's. And it can't
 * define if domain name is really exist or can exist. This function just
 * performs syntax check.
 *
 * @param {string} host String to test.
 * @return {boolean} True if domain name is correct or false otherwise.
 */
const isDomain = host => {
    /*
        Function grabbed with little modifications from
        https://github.com/chriso/validator.js/blob/master/lib/isFQDN.js
        which is a part of `validator` npm package:
        https://www.npmjs.com/package/validator
    */

    if (host[host.length - 1] === '.') {
        host = host.substring(0, host.length - 1);
    }

    const parts = host.split('.');

    for (let i = 0; i < parts.length; i++) {
        if (parts[i].length > 63) {
            return false;
        }
    }

    const tld = parts.pop();

    if (!parts.length || !/^([a-z\u00a1-\uffff]{2,}|xn[a-z0-9-]{2,})$/i.test(tld)) {
        return false;
    }

    if (/[\s\u2002-\u200B\u202F\u205F\u3000\uFEFF\uDB40\uDC20]/.test(tld)) {
        return false;
    }

    for (let i = 0; i < parts.length; i++) {
        const part = parts[i];

        if (!/^[a-z\u00a1-\uffff0-9-]+$/i.test(part)) {
            return false;
        }

        if (/[\uff01-\uff5e]/.test(part)) {
            return false;
        }

        if (part[0] === '-' || part[part.length - 1] === '-') {
            return false;
        }
    }

    return true;
};


/**
 * Get host info of domain name like `host -a` command.
 *
 * @param {string} host Domain name.
 * @return {Promise} Promise where then() takes function with object like this:
 *                {
 *                    'A'    : ['IPv4-addresses'],
 *                    'AAAA' : ['IPv6-addresses'],
 *                    'MX'   : ['MX-records'    ],
 *                    'TXT'  : ['TXT-records'   ],
 *                    'SRV'  : ['SRV-records'   ],
 *                    'NS'   : ['NS-records'    ],
 *                    'CNAME': ['CNAME-records' ],
 *                    'NAPTR': ['CNAME-records' ],
 *                    'PTR':   ['CNAME-records' ],
 *                    'SOA'  : ['SOA-records'   ]
 *                }
 */
const nslookup = async host => {
    if (!isDomain(host)) {
        throw new Error(`Not domain name: ${host}`);
    }

    // need for IDN domain names but doesn't matter if used on ASCII names
    host = punycode.toASCII(host);

    // types of requests to perform (all possible types)
    const rrtypes = ['A', 'AAAA', 'CNAME', 'MX', 'NAPTR', 'NS', 'PTR', 'SOA', 'SRV', 'TXT'];

    // promises to resolve domain name of all possible rrtypes
    const resolves = rrtypes.map(async rrtype =>  {
        let request = null;
        try {
            request = await dns.resolve(host, rrtype);
        } catch(err) {
            request = null;
        }

        return request;
    });

    // perform resolve
    const resolved = await Promise.all(resolves);

    // collect all rrtypes resolves in one object
    const result = resolved.reduce((prev, curr, index) => {
        if (curr) {
            if (rrtypes[index] === 'TXT') {
                curr = curr.map(lines => lines.join('\n'));
            }

            prev[rrtypes[index]] = curr;
        }

        return prev;
    }, {});

    return result;
};


/**
 * Perform whois request.
 *
 * @param {string} host Domain name or IP-address.
 * @return {object} Promise where then() takes function with whois text.
 */
const whois = (host, options = {}) => {
    return new Promise((resolve, reject) => {
        node_whois.lookup(host, options, (err, data) => {
            if (err) {
                return void reject(err);
            }

            return void resolve(data);
        });
    });
};


/**
 * Reverse IP address for some special DNS requests. Works both for IPv4 and
 * IPv6.
 *
 * Examples:
 *     IPv4: 1.2.3.4 -> 4.3.2.1
 *     IPv6:
 *         2001:0db8:11a3:09d7:1f34:8a2e:07a0:765d ->
 *               d.5.6.7.0.a.7.0.e.2.a.8.4.3.f.1.7.d.9.0.3.a.1.1.8.d.b.0.1.0.0.2
 *         2001:db8::ae21:ad12 ->
 *               2.1.d.a.1.2.e.a.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.d.b.0.1.0.0.2
 *
 * @param {string} ip IP address to reverse.
 * @return {string} Reversed IP address. If parameter is not IP-address then
 *                  return itself.
 */
const ipReverse = ip => {
    const ipaddr = ip.trim();

    // IPv4
    if (net.isIPv4(ipaddr)) {
        return ipaddr
            .split('.')
            .reverse()
            .join('.');
    }

    // IPv6
    if (net.isIPv6(ipaddr)) {
        return ipaddr
            .split(':')
            .reduce((prev, curr, i, arr) => {
                // replace '::' with several '0000'
                if (curr.length === 0) {
                    // should be 8 words (1 word is 2 bytes), and we have
                    // array with several words and one empty element
                    // so we replace empty element with words like '0000' to
                    // satisfy total count of words
                    return prev.concat('0000'.repeat(9 - arr.length));
                }

                // left pad with '0' to length of 4
                return prev.concat('0'.repeat(4 - curr.length), curr);
            }, '')
            .split('')
            .reverse()
            .join('.');
    }

    // not IP
    return ip;
};


/**
 * Check if IP address is a TOR node.
 *
 * @param {string} ip IP-address.
 * @return {object} Promise where then() takes function with object like this:
 *                {
 *                    'nodename': 'Name of TOR node',
 *                    'port'    : [0], //port numbers of TOR node
 *                    'exitNode': true //if true then this is exit node
 *                }
 *                If IP does not belong to TOR node then null will be passed
 *                instead of described object.
 */
const torInfo = async ip => {
    const ipaddr = ip.trim();

    if (!net.isIPv4(ipaddr)) {
        throw new Error(`Not valid IPv4: ${ipaddr}`);
    }

    // special server to check TOR node IPs
    const TORServer = 'tor.dan.me.uk';

    // host to resolve using DNS query
    const host = ipReverse(ipaddr).concat('.', TORServer);

    // perform request
    let dns_A = null;
    try {
        dns_A = await dns.resolve(host, 'A');
    } catch(err) {
        return null;
    }

    // not a TOR node
    if (!dns_A) {
        return null;
    }

    // get info about TOR node
    let dns_TXT = null;
    try {
        dns_TXT = (await dns.resolve(host, 'TXT')).map(lines => lines.join(''));
    } catch(err) {
        return null;
    }

    // no info about TOR node
    if (!dns_TXT || !(0 in dns_TXT)) {
        return null;
    }

    // RegExp to parse NS response
    const RE_INFO = /N:([^\/]+)\/P:(\d+(,\d+|))\/F:([EXABDFGHNRSUV]*)/;

    // parse NS response
    let matches = RE_INFO.exec(dns_TXT[0]);
    if (!matches) {
        return null;
    }

    const result = {
        nodename: matches[1],
        port    : matches[2].split(','),
        exitNode: matches[4].indexOf('E') !== -1 || matches[4].indexOf('X') !== -1
    };

    return result;
};


/**
 * Reqular expressions to match IPv4 and IPv6 addresses.
 * Need for extractIP() and extractIPGen()
 */
const EXTRACT_IP_REGEXP = [
    /((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])/g

    // get it from http://stackoverflow.com/questions/53497/regular-expression-that-matches-valid-ipv6-addresses
    , new RegExp(
        '(' +
        '([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|' +          // 1:2:3:4:5:6:7:8
        '([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|' +         // 1::8             1:2:3:4:5:6::8  1:2:3:4:5:6::8
        '([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|' +  // 1::7:8           1:2:3:4:5::7:8  1:2:3:4:5::8
        '([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|' +  // 1::6:7:8         1:2:3:4::6:7:8  1:2:3:4::8
        '([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|' +  // 1::5:6:7:8       1:2:3::5:6:7:8  1:2:3::8
        '([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|' +  // 1::4:5:6:7:8     1:2::4:5:6:7:8  1:2::8
        '[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|' +       // 1::3:4:5:6:7:8   1::3:4:5:6:7:8  1::8
        ':((:[0-9a-fA-F]{1,4}){1,7}|:)|' +                     // ::2:3:4:5:6:7:8  ::2:3:4:5:6:7:8 ::8       ::
        '([0-9a-fA-F]{1,4}:){1,7}:|' +                         // 1::                              1:2:3:4:5:6:7::
        'fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|' +     // fe80::7:8%eth0   fe80::7:8%1     (link-local IPv6 addresses with zone index)
        '::(ffff(:0{1,4}){0,1}:){0,1}' +
        '((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]).){3,3}' +
        '(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|' +          // ::255.255.255.255   ::ffff:255.255.255.255  ::ffff:0:255.255.255.255  (IPv4-mapped IPv6 addresses and IPv4-translated addresses)
        '([0-9a-fA-F]{1,4}:){1,4}:' +
        '((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]).){3,3}' +
        '(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])' +           // 2001:db8:3:4::192.0.2.33  64:ff9b::192.0.2.33 (IPv4-Embedded IPv6 Address)
        ')'
        , 'ig'
    )
];


/**
 * Extract IP-addresses from raw text.
 *
 * @param {string} str String to extract IP-addresses from.
 * @return {Promise} Promise where then() takes function with array of
 *                   IP-addresses as strings.
 */
const extractIP = str => {
    return new Promise((resolve, reject) => {
        // list of IP addresses
        let ipList = new Set();

        /**
         * ******************************************************************* *
         *                         INTERNAL FUNCTION                           *
         * ******************************************************************* *
         *
         * Function to execute every event loop. Need to avoid blocking.
         *
         * @param object options Object with list of RegExp to exec and index of
         *                       RegExp to execute within given list:
         *                       {
         *                           re   : [ RegExp ],
         *                           index: 0
         *                       }
         */
        const fn = options => {
            // execute RegExp
            let match = options.re[options.index].exec(str);

            // match found
            if (match) {
                // add found IP
                ipList.add(match[0]);

                // next iteration
                setImmediate(fn, options);

            // no match, next iteration or end of loop
            } else {
                // try next RegExp from options.re array
                if (options.re.length > ++options.index) {
                    setImmediate(fn, options);

                // no more RegExp in options.re array
                } else {
                    resolve([...ipList]);
                }
            }
        };

        // start loop
        setImmediate(fn, {re: EXTRACT_IP_REGEXP, index: 0});
    });
};


/**
 * Initialize script to get GeoIP information.
 *
 * @param {string} dbPath Path to GeoIP files.
 * @return {Object} Promise.
 */
const geoInit = async (dbPath) => {
    const MAXMIND          = 'GeoLite2-City.mmdb';
    const MAXMIND_ASN      = 'GeoLite2-ASN.mmdb';
    const IP2LOCATON       = 'IP2LOCATION-LITE-DB5.IPV6.BIN';
    const IP2LOCATON_PROXY = 'IP2PROXY-LITE-PX4.BIN';

    // do not initialize library twice, instantly resolve instead
    if (geoInitialized) {
        return;
    }

    // init ip2location and ip2location Proxy
    ip2loc.IP2Location_init(path.join(dbPath, IP2LOCATON));
    ip2proxy.Open(          path.join(dbPath, IP2LOCATON_PROXY));

    // init MaxMind
    [maxMind, maxMind_asn] = await Promise.all([
        mmdbReader.open(path.join(dbPath, MAXMIND)),
        mmdbReader.open(path.join(dbPath, MAXMIND_ASN))
    ]);

    return;
};


/**
 * Get GeoIP information.
 *
 * @param {string} host IP address to get info about.
 * @return {Promise} Promise Promise where then() has object as parameter like
 *                           in this example:
 *                        {
 *                            ip          : '78.46.112.219',
 *                            asn         : '24940',
 *                            as_org      : 'Hetzner Online GmbH',
 *                            proxy       : 'VPN', // see https://www.ip2proxy.com/ for possible values
 *                            country_code: ['DE'],
 *                            country     : ['Germany'],
 *                            region      : [ 'Bayern', 'Bavaria', 'Sachsen' ],
 *                            city        : [ 'Nürnberg', 'Nuremberg', 'Falkenstein' ],
 *                            country_ru  : 'Германия',
 *                            region_ru   : 'Бавария',
 *                            city_ru     : 'Нюрнберг',
 *                            timezone    : 'Europe/Berlin',
 *                            coords      : [
 *                                { lat: 49.4478, lon: 11.068299999999994 },
 *                                { lat: 49.4478, lon: 11.0683 }
 *                            ]
 *                        }
 */
const geoInfo = async host => {
    // not IP address
    if (!isIP(host)) {
        return void reject(new Error(`Not IP address: ${host}`));
    }

    // perform requests to all DB
    const data = await Promise.all([
        maxMind.city.bind(maxMind),
        ip2loc.IP2Location_get_all,
        maxMind_asn.asn.bind(maxMind_asn),
        ip2proxy.getAll
    ].map(fn => { try { return fn(host); } catch (err) { return null; } }));

    // result
    const result = {
        ip          : host,
        asn         : null,
        as_org      : null,
        proxy       : null,
        country_code: new Set(),
        country     : new Set(),
        country_ru  : null,
        region      : new Set(),
        region_ru   : null,
        city        : new Set(),
        city_ru     : null,
        timezone    : null,
        coords      : []
    };

    // fill from 'MaxMind' DB
    if (data[0] !== null) {
        // country
        if ('country' in data[0]) {
            if ('names' in data[0].country) {
                result.country.add(data[0].country.names.en);
                result.country_ru = data[0].country.names.ru;
            }

            if ('isoCode' in data[0].country) {
                result.country_code.add(data[0].country.isoCode );
            }
        }

        // region
        if (Array.isArray(data[0].subdivisions) && data[0].subdivisions.length > 0) {
            result.region.add(data[0].subdivisions[0].names.en);

            if (typeof data[0].subdivisions[0].names.ru !== 'undefined') {
                result.region_ru = data[0].subdivisions[0].names.ru;
            }
        }

        // city
        if (('city' in data[0]) && ('names' in data[0].city)) {
            result.city.add(data[0].city.names.en);

            if (typeof data[0].city.names.ru !== 'undefined')
                result.city_ru = data[0].city.names.ru;
        }

        // coords
        result.coords.push({
            lat: data[0].location.latitude,
            lon: data[0].location.longitude
        });

        // timezone
        if (typeof data[0].location.time_zone !== 'undefined') {
            result.timezone = data[0].location.timeZone;
        }
    }

    // fill from 'IP2Location' DB
    if (data[1] !== null) {
        result.country.add(     data[1].country_long );
        result.country_code.add(data[1].country_short);
        result.region.add(      data[1].region       );
        result.city.add(        data[1].city         );

        if (data[1].latitude !== 0 && data[1].longitude !== 0) {
            result.coords.push({
                lat: data[1].latitude,
                lon: data[1].longitude
            });
        }
    }

    // fill from 'MaxMind ASN' DB
    if (data[2] !== null) {
        result.asn    = data[2].autonomousSystemNumber ;
        result.as_org = data[2].autonomousSystemOrganization;
    }

    // fill from 'IP2Location Proxy' DB
    if (data[3] !== null && data[3].Proxy_Type.length > 1) {
        result.proxy = data[3].Proxy_Type;
    }

    // convert Sets to Arrays
    result.country_code = [...result.country_code];
    result.country      = [...result.country     ];
    result.region       = [...result.region      ];
    result.city         = [...result.city        ];


    return result;
};


/**
 * Update MaxMind and IP2Location databases.
 *
 * @param {string} dbPath Full local path to store DB files
 * @param {string} token API token to download IP2Location database
 */
const geoUpdate = async (dbPath, token) => {
    const MAXMIND = {
        URL        : 'https://geolite.maxmind.com/download/geoip/database/GeoLite2-City.tar.gz',
        FILENAME   : path.join(dbPath, 'GeoLite2-City.tar.gz'),
        BASENAME   : path.join(dbPath, 'GeoLite2-City.mmdb'),
        COMPRESSION: 'gzip'
    };

    const MAXMIND_ASN = {
        URL        : 'https://geolite.maxmind.com/download/geoip/database/GeoLite2-ASN.tar.gz',
        FILENAME   : path.join(dbPath, 'GeoLite2-ASN.tar.gz'),
        BASENAME   : path.join(dbPath, 'GeoLite2-ASN.mmdb'),
        COMPRESSION: 'gzip'
    };

    const IP2LOCATON = {
        URL        : `https://www.ip2location.com/download?file=DB5LITEBINIPV6&token=${token}`,
        FILENAME   : path.join(dbPath, 'IP2LOCATION-LITE-DB5.IPV6.ZIP'),
        BASENAME   : path.join(dbPath, 'IP2LOCATION-LITE-DB5.IPV6.BIN'),
        COMPRESSION: 'zip'
    };

    const IP2LOCATON_PROXY = {
        URL        : `https://www.ip2location.com/download?file=PX4LITEBIN&token=${token}`,
        FILENAME   : path.join(dbPath, 'IP2PROXY-LITE-PX4.BIN.ZIP'),
        BASENAME   : path.join(dbPath, 'IP2PROXY-LITE-PX4.BIN'),
        COMPRESSION: 'zip'
    };

    const promises = [MAXMIND, MAXMIND_ASN, IP2LOCATON, IP2LOCATON_PROXY]
        .map(DB => new Promise((resolve, reject) => {
            https.get(DB.URL, res => {
                res.pipe(fs.createWriteStream(DB.FILENAME));

                res.on('end', async () => {
                    if (DB.COMPRESSION === 'zip') {
                        const buf = await fs.promises.readFile(DB.FILENAME);
                        const zip = await jszip.loadAsync(buf);
                        zip.forEach((name, file) => {
                            if (DB.BASENAME.includes(name)) {
                                file.nodeStream()
                                    .pipe(fs.createWriteStream(DB.BASENAME))
                                    .on('error', reject)
                                    .on('finish', resolve);
                            }
                        });
                    } else if (DB.COMPRESSION === 'gzip') {
                        const inp = fs.createReadStream(DB.FILENAME);
                        const out = fs.createWriteStream(DB.BASENAME);

                        const gunzip = zlib.createGunzip();

                        const extract = tar.extract();
                        extract.on('entry', (header, stream, next) => {
                            const filename = header.name.split('/')[1];

                            if((filename !== '') && DB.BASENAME.includes(filename)) {
                                stream.pipe(out);
                            }

                            stream.on('end', next);
                            stream.resume();
                        });

                        inp.pipe(gunzip).pipe(extract)
                            .on('error', reject)
                            .on('finish', resolve);
                    }
                });
            })
            .on('error', reject);
        }));

    await Promise.all(promises);
};


/**
 * Get BGP information, such as Autonomous System number. You can get this info
 * manually by using this command in Linux console:
 * $ dig +short 224.135.219.83.origin.asn.cymru.com. TXT
 * $ dig +short AS31999.asn.cymru.com. TXT
 *
 * @param {string} host IP address to get info about.
 * @return {Promise} Promise.
 */
const bgpInfo = async host => {
    const ip = host.trim();

    // special servers to check BGP info
    const bgpServer4  = 'origin.asn.cymru.com';
    const bgpServer6  = 'origin6.asn.cymru.com';
    const bgpAsServer = 'asn.cymru.com';

    let bgpRequestHost;

    if (net.isIPv4(ip)) {
        bgpRequestHost = ipReverse(ip).concat('.', bgpServer4);

    } else if (net.isIPv6(ip)) {
        bgpRequestHost = ipReverse(ip).concat('.', bgpServer6);

    // not IP
    } else {
        return reject(new Error(`Not valid IPv4: ${ip}`));
    }

    const bgpObject = {
        'as'             : null,
        'ip'             : ip,
        'prefix'         : null,
        'country_code'   : null,
        'registry'       : null,
        'allocation_date': null,
        'name'           : null
    }
    const result = [];

    // get 'AS', 'BGP Prefix', 'CC', 'Registry', 'Allocated'
    const response = await dns.resolve(bgpRequestHost, 'TXT');

    // empty answer
    if (
        (response === null) ||
        !(0 in response)    ||
        !(0 in response[0])
    ) {
        return null;
    }

    // construct result
    let response_arr = response[0][0].split(' | ');
    const as_nums = response_arr[0].split(' ');
    bgpObject.prefix          = response_arr[1];
    bgpObject.country_code    = response_arr[2];
    bgpObject.registry        = response_arr[3];
    bgpObject.allocation_date = response_arr[4];

    // get 'AS Name'
    for (const as of as_nums) {
        const bgp = {...bgpObject};
        bgp.as = as;

        bgpRequestHost = `AS${as}.${bgpAsServer}`;
        const response = await dns.resolve(bgpRequestHost, 'TXT');
        if (
            (response !== null) &&
            (0 in response)     &&
            (0 in response[0])
        ) {
            response_arr = response[0][0].split(' | ');
            bgp.name = response_arr[4];
        }

        result.push(bgp);
    }

    return result;
};


/**
 * Try to get all possible info about domain name or IP-address.
 *
 * @param {string} host Domain name or IP-address.
 * @return {object} Promise where `then()` has the following object as parameter:
 *                {
 *                    host    : host,
 *                    isIP    : true,
 *                    longIP  : null,
 *                    reverse : null,
 *                    geoInfo : null,
 *                    torInfo : null,
 *                    bgpInfo : null,
 *                    isDomain: false,
 *                    nslookup: null,
 *                    whois   : null
 *                }
 */
const hostInfo = async host => {
    // result skeleton
    const result = {
        host   : host,
        isIP   : true,
        longIP : null,
        reverse: null,
        geoInfo: null,
        torInfo: null,
        bgpInfo: null,

        isDomain: false,
        nslookup: null,

        whois: null
    };

    // collect available info about IP
    if (isIP(host)) {
        result.isIP     = true;
        result.isDomain = false;
        result.longIP   = ip2long(host);

        const info = await Promise.all(
            [dns.reverse, geoInfo, torInfo, bgpInfo, whois]
            .map(promise => promise(host))
            .map(promise => promise.catch(err => null))
        );

        result.reverse = info[0];
        result.geoInfo = info[1];
        result.torInfo = info[2];
        result.bgpInfo = info[3];
        result.whois   = info[4];

    // collect available info about domain
    } else {
        result.isIP     = false;
        result.isDomain = true;

        const info = await Promise.all(
            [nslookup, whois]
            .map(promise => promise(host))
            .map(promise => promise.catch(err => null))
        );

        result.nslookup = info[0];
        result.whois    = info[1];
    }

    return result;
};


exports.ip2long   = ip2long;
exports.isIP      = isIP;
exports.isDomain  = isDomain;
exports.ipReverse = ipReverse;
exports.reverse   = dns.reverse;
exports.nslookup  = nslookup;
exports.whois     = whois;
exports.torInfo   = torInfo;
exports.extractIP = extractIP;
exports.geoInit   = geoInit;
exports.geoInfo   = geoInfo;
exports.geoUpdate = geoUpdate;
exports.bgpInfo   = bgpInfo;
exports.info      = hostInfo;
