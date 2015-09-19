'use strict'
const events     = require('events');
const dns        = require('dns');
const net        = require('net');
const punycode   = require('punycode');
const validator  = require('validator');
const fs         = require('fs');
const path       = require('path');
const ip2loc     = require('ip2location-nodejs');
const node_whois = require('node-whois');
const geoip      = require('maxmind');
const mmdbreader = require('maxmind-db-reader');


// GeoIP info
let geoIPInfo  = null;
let geoIP2Info = null;


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
 * @param string ip IPv4-address in one of possible representations.
 * @return Number The 32-bit number notation of IP-address expressed in decimal.
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
}


/**
 * Detect if host is correct IP-address.
 *
 * @param host String to test.
 * @return bool
 */
const isIP = host => net.isIP(host) !== 0


/**
 * Detect if host is correct domain name. It can't test IDN's. And it can't
 * define if domain name is really exist or can exist. This function just
 * performs syntax check.
 *
 * @param string host String to test.
 * @return bool True if domain name is correct or false otherwise.
 */
const isDomain = host => {
    const options = {
        require_tld       : true,
        allow_underscores : false,
        allow_trailing_dot: true
    };

    return validator.isFQDN(host, options);
}


/**
 * Define domain names by IP-address using reverse domain request.
 *
 * @param string ip IP-address to reverse.
 * @return Promise Promise where then() takes function with array of hostnames.
 */
const reverse = ip => {
    return new Promise((resolve, reject) => {
        dns.reverse(ip, (err, hostnames) => {
            if(err !== null) {
                reject(err);
                return;
            }

            resolve(hostnames);
        });
    });
}


/**
 * *************************************************************************** *
 *                           INTERNAL FUNCTION                                 *
 * *************************************************************************** *
 *
 * dns.resolve() function converted to Promise version. Note that it never
 * rejects but returns null in then() callback on errors.
 */
const dns_resolve = (hostname, rrtype) => {
    return new Promise(resolve => {
        dns.resolve(hostname, rrtype, (err, addresses) => {
            if (err === null)
                resolve({
                    rrtype   : rrtype,
                    addresses: addresses
                });
            else
                resolve(null);
        });
    });
}


/**
 * Get host info of domain name like `host -a` command.
 *
 * @param string host Domain name.
 * @return object Promise where then() takes function with object like this:
 *                {
 *                    'A'    : ['IPv4-addresses'],
 *                    'AAAA' : ['IPv6-addresses'],
 *                    'MX'   : ['MX-records'    ],
 *                    'TXT'  : ['TXT-records'   ],
 *                    'SRV'  : ['SRV-records'   ],
 *                    'NS'   : ['NS-records'    ],
 *                    'CNAME': ['CNAME-records' ],
 *                    'SOA'  : ['SOA-records'   ]
 *                }
 */
const nslookup = host => {
    return new Promise((resolve, reject) => {
        if (!isDomain(host)) {
            reject(new Error(`Not domain name: ${host}`));
            return;
        }

        // need for IDN domain names but doesn't matter if used on ASCII names
        host = punycode.toASCII(host);

        // types of requests to perform (all possible types)
        const rrtypes = ['A', 'AAAA', 'MX', 'TXT', 'SRV', 'NS', 'CNAME', 'SOA']

        // promises to resolve domain name of all possible rrtypes
        const resolves = rrtypes.map(rrtype => {
            return dns_resolve(host, rrtype);
        });

        // collect all rrtypes resolves in one object
        Promise.all(resolves).then(values => {
            let result = {};

            values.forEach(v => {
                if (v === null) return;
                result[v.rrtype] = v.addresses;
            });

            // for TXT records avoid internal arrays: [ [txt], [txt] ] => [txt, txt]
            if ('TXT' in result)
                result['TXT'] = result['TXT'].map(elem => elem.join('\n'));

            resolve(result);
        });
    });
}


/**
 * Perform whois request.
 *
 * @param string host Domain name or IP-address.
 * @return object Promise where then() takes function with whois text.
 */
const whois = host => {
    return new Promise((resolve, reject) => {
        node_whois.lookup(host.toLowerCase(), (err, data) => {
            if (err !== null) {
                reject(err);
                return;
            }

            resolve(data);
        });
    });
}


/**
 * Check if IP address is a TOR node.
 *
 * @param string ip IP-address.
 * @return object Promise where then() takes function with object like this:
 *                {
 *                    'nodename': 'Name of TOR node',
 *                    'port'    : [0], //port numbers of TOR node
 *                    'exitNode': true //if true then this is exit node
 *                }
 *                If IP does not belong to TOR node then null will be passed
 *                instead of described object.
 */
const torInfo = ip => {
    return new Promise((resolve, reject) => {
        if (!net.isIPv4(ip)) {
            reject(new Error(`Not valid IPv4: ${ip}`));
        }

        // special server to check TOR node IPs
        const TORServer = 'tor.dan.me.uk';

        // reverse IP: 1.2.3.4 -> 4.3.2.1
        const reversedIP = ip.split('.').reverse().join('.');

        // host to resolve using DNS query
        const host = `${reversedIP}.${TORServer}`;

        // perform request
        dns_resolve(host, 'A')

        // check if IP is TOR node
        .then(response => {
            // not a TOR node
            if (response === null) {
                resolve(null);
                return null;
            }

            // get info about TOR node
            return dns_resolve(host, 'TXT');
        })

        // info about TOR node
        .then(response => {
            if (   response === null
                || !('addresses' in response)
                || !(0 in response.addresses)
                || !(0 in response.addresses[0])
            ) {
                resolve(null);
                return;
            }

            // RegExp to parse NS response
            const re = /N:([^\/]+)\/P:(\d+(,\d+|))\/F:([EABDFGHNRSUV]*)/

            // parse NS response
            let matches = re.exec(response.addresses[0][0]);
            if (matches === null) {
                resolve(null);
                return;
            }

            resolve({
                nodename: matches[1],
                port    : matches[2].split(','),
                exitNode: matches[4].indexOf('E') !== -1
            });
        });
    });
}



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
 * @param string str String to extract IP-addresses from.
 * @return Promise Promise where then() takes function with array of
 *                 IP-addresses as strings.
 */
const extractIP = str => {
    return new Promise((resolve, reject) => {
        // list of IP addresses
        let ipList = [];

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
        const fn = (options) => {
            // execute RegExp
            let match = options.re[options.index].exec(str);

            // match found
            if (match !== null) {
                // add found IP
                if (ipList.indexOf(match[0]) === -1) ipList.push(match[0]);

                // next iteration
                setImmediate(fn, options);

            // no match, next iteration or end of loop
            } else
                // try next RegExp from options.re array
                if (options.re.length > ++options.index)
                    setImmediate(fn, options);

                // no more RegExp in options.re array
                else
                    resolve(ipList);
        };

        // start loop
        setImmediate(fn, { re: EXTRACT_IP_REGEXP, index: 0 });
    });
}


/**
 * Extract IP-addresses from raw text.
 *
 * Note that this generator function is approximately five times slower than
 * extractIP() promise function.
 *
 * @param string str String to extract IP-addresses from.
 * @return Generator On every next() call it will return IP address. All
 *                   returned IP are unique.
 */
const extractIPGen = function* (str) {
    // need to save all IP we fetched to return every IP only once
    let ipList = [];

    // try every pattern
    for (let re of EXTRACT_IP_REGEXP) {
        let match;

        // execute RegExp
        while (null !== (match = re.exec(str)))

            // found IP was not found earlier, save and return it
            if (ipList.indexOf(match[0]) === -1) {
                ipList.push(match[0]);
                yield match[0];
            }
    }
}


/**
 * *************************************************************************** *
 *                           INTERNAL FUNCTION                                 *
 * *************************************************************************** *
 *
 * Prepare ip2location DB file by joining files into one.
 * @param string dbPath Path to DB files.
 * @param string ip2locationFileName Name of joined IP2Location DB file.
 * @param array files File names to join into one in order to join.
 * @return object Promise where then() will be callen when ip2location DB file
 *                is ready.
 */
const ip2locPrepareFiles = (dbPath, ip2locationFileName, files) => {
    return new Promise((resolve, reject) => {
        // remove ip2location DB file if exists
        try {
            fs.unlinkSync(path.join(dbPath, ip2locationFileName));
        } catch(err) {}

        // write ip2location DB with data of input files
        let i = 0;
        const fn = () => {
            fs.createReadStream(path.join(dbPath, files[i]))
            .on('error', err => reject(err))
            .pipe(
                fs
                .createWriteStream(path.join(dbPath, ip2locationFileName), { flags: 'a' })
                .on('error', err => reject(err))
                .on('finish', () => {
                    if (++i < files.length)
                        fn();
                    else
                        resolve();
                })
            );
        }
        fn();
    });
}


/**
 * Initialize script to get GeoIP information.
 *
 * @param string dbPath Path to GeoIP files.
 * @param object files Object with the following structure:
 *                     {
 *                         ip2location: {
 *                             db: 'ip2location.bin',
 *
 *                             // IPv6 first!!!
 *                             source: [
 *                                 'IP2LOCATION-LITE-DB5.IPV6.BIN',
 *                                 'IP2LOCATION-LITE-DB5.BIN'
 *                             ]
 *                         },
 *                         maxMind: {
 *                             city: 'GeoLiteCity.dat',
 *                             org : 'GeoIPASNum.dat'
 *                         },
 *                         maxMindv6: {
 *                             city: 'GeoLiteCityv6.dat',
 *                             org : 'GeoIPASNumv6.dat'
 *                         },
 *                         maxMind2: 'GeoLite2-City.mmdb'
 *                     }
 * @return object Promise
 */
const geoInit = (dbPath, files) => {
    return new Promise((resolve, reject) => {
        // create one file of ip2location databases
        ip2locPrepareFiles(dbPath, files.ip2location.db, files.ip2location.source)
        .then(() => {
            // init ip2location
            ip2loc.IP2Location_init(path.join(dbPath, files.ip2location.db));

            // init GeoIP Legacy
            geoip.init(
                [
                      path.join(dbPath, files.maxMind.city)
                    , path.join(dbPath, files.maxMindv6.city)
                    , path.join(dbPath, files.maxMind.org)
                    , path.join(dbPath, files.maxMindv6.org)
                ],

                // store DB in memory for faster access
                { memoryCache: true }
            );

            // init GeoIP2
            mmdbreader.open(path.join(dbPath, files.maxMind2), (err, geoIP2) => {
                if (err !== null) {
                    reject(err);
                    return;
                }

                geoIP2Info = geoIP2;
                resolve();
            });
        })
        .catch(err => {
            reject(err);
        });
    });
}


/**
 * Get GeoIP information.
 *
 * @param string host IP address to get info about.
 * @return object Promise Promise where then() has object as parameter like
 *                        in this example:
 *                        {
 *                            ip          : '78.46.112.219',
 *                            as          : 'AS24940 Hetzner Online GmbH',
 *                            country     : 'Germany',
 *                            country_ru  : 'Германия',
 *                            country_code: 'DE',
 *                            region      : [ 'Bayern', 'Bavaria', 'Sachsen' ],
 *                            region_ru   : 'Бавария',
 *                            city        : [ 'Nürnberg', 'Nuremberg', 'Falkenstein' ],
 *                            city_ru     : 'Нюрнберг',
 *                            timezone    : 'Europe/Berlin',
 *                            coords      : [
 *                                { lat: 49.4478, lon: 11.068299999999994 },
 *                                { lat: 49.4478, lon: 11.0683 },
 *                                { lat: 50.47787857055664, lon: 12.37129020690918 }
 *                            ]
 *                        }
 */
const geoInfo = (host) => {
    return new Promise((resolve, reject) => {
        // not IP address
        if (!isIP(host)) {
            reject(new Error(`Not IP address: ${host}`));
            return;
        }

        // perform requests to all DB
        Promise.all([
            // GeoIP city
            Promise.resolve(geoip.getLocation(host)),

            // GeoIP AS number
            Promise.resolve(geoip.getAsn(host)),

            // GeoIP2 API
            new Promise((resolve) => {
                geoIP2Info.getGeoData(host, (err, data) => {
                    resolve(err !== null ? null : data);
                });
            }),

            // IP2Location API
            Promise.resolve(ip2loc.IP2Location_get_all(host))
        ])

        // got answers from all DB
        .then((data) => {
            // result object skeleton
            let result = {
                ip          : host,
                as          : null,
                country     : null,
                country_ru  : null,
                country_code: null,
                region      : null,
                region_ru   : null,
                city        : null,
                city_ru     : null,
                timezone    : null,
                coords      : []
            };


            /**
             * *************************************************************** *
             *                      INTERNAL FUNCTION                          *
             * *************************************************************** *
             *
             * Need to update result object using information from different
             * databases using so called waves.
             *
             * If curr is not null and not '-' then it compares to prev.
             * If prev is string and curr is equal to prev then prev returned.
             * If prev is string and curr is not equal to prev then array with
             * two elements [prev, curr] returned.
             * If prev is array and contain curr then prev returned.
             * If prev is array and does not contain curr then curr will be
             * pushed to prev and resulting array will be returned.
             */
            const addIfDiffers = (prev, curr) => {
                if (curr === null || curr === '-')
                    return prev;

                if (prev === null) return curr;

                // prev is probably a string
                if (!Array.isArray(prev))
                    return prev === curr ? prev : [prev, curr];

                // prev is array
                else
                    return prev.indexOf(curr) >= 0 ? prev : prev.concat([curr]);
            };


            // fill from 'GeoIP city' DB
            if (data[0] !== null) {
                result.country      = data[0].countryName;
                result.country_code = data[0].countryCode;
                result.region       = data[0].regionName;
                result.city         = data[0].city;

                result.coords.push({
                    lat: data[0].latitude ,
                    lon: data[0].longitude
                });
            }

            // fill from 'GeoIP ASNum' DB
            if (data[1] !== null) {
                result.as = data[1];
            }

            // fill from 'GeoIP2' DB
            if (data[2] !== null) {
                result.country      = addIfDiffers(result.country     , data[2].country.names.en);
                result.country_code = addIfDiffers(result.country_code, data[2].country.iso_code);
                result.country_ru   = data[2].country.names.ru;

                // region international names
                if (Array.isArray(data[2].subdivisions) && data[2].subdivisions.length > 0) {
                    result.region = addIfDiffers(result.region, data[2].subdivisions[0].names.en);

                    if (typeof data[2].subdivisions[0].names.ru !== 'undefined')
                        result.region_ru = data[2].subdivisions[0].names.ru;
                }

                // city international names
                if (typeof data[2].city !== 'undefined') {
                    result.city = addIfDiffers(result.city, data[2].city.names.en);

                    if (typeof data[2].city.names.ru !== 'undefined')
                        result.city_ru = data[2].city.names.ru;
                }

                result.coords.push({
                    lat: data[2].location.latitude ,
                    lon: data[2].location.longitude
                });

                if (typeof data[2].location.time_zone !== 'undefined')
                    result.timezone = data[2].location.time_zone;
            }

            // fill from 'IP2Location' DB
            if (data[3] !== null) {
                result.country      = addIfDiffers(result.country     , data[3].country_long);
                result.country_code = addIfDiffers(result.country_code, data[3].country_short);
                result.region       = addIfDiffers(result.region      , data[3].region);
                result.city         = addIfDiffers(result.city        , data[3].city);

                if (data[3].latitude !== 0 && data[3].longitude !== 0)
                    result.coords.push({
                        lat: data[3].latitude ,
                        lon: data[3].longitude
                    });
            }

            resolve(result);
        })
        .catch(err => reject(err));
    });
}


/**
 * Get BGP information, such as Autonomous System number. You can get this info
 * manually by using this command in Linux console:
 * $ echo "-c -r -a -u -p 109.111.139.45" | nc whois.cymru.com 43
 *
 * @param string host IP address to get info about.
 * @return object Promise.
 */
const bgpInfo = (host) => {
    return new Promise((resolve, reject) => {
        // several constants
        const BGP_WHOIS      = 'whois.cymru.com';
        const BGP_WHOIS_PORT = 43;
        const BGP_WHOIS_CMD  = '-c -r -a -u -p ${host}\n';
        const BGP_TITLES = {
            'AS'        : 'as',
            'IP'        : 'ip',
            'BGP Prefix': 'prefix',
            'CC'        : 'country_code',
            'Registry'  : 'registry',
            'Allocated' : 'allocation_date',
            'AS Name'   : 'name'
        };


        // not IP address
        if (!isIP(host)) {
            reject(new Error(`Not IP address: ${host}`));
            return;
        }

        // buffer to read from socket
        let buf = '';

        // create socket and connect to special whois server
        const sock = new net.Socket();
        sock.connect({
            host: BGP_WHOIS,
            port: BGP_WHOIS_PORT
        })
        .setEncoding('utf8')
        .on('error', err => reject(err))
        .on('data', chunk => buf += chunk)

        // parse data
        .on('end', () => {
            if (buf.length === 0) {
                reject(new Error(`Empty answer from '${sock.remoteAddress}': ${host}`));
                return;
            }

            // extract data
            let data =
                buf
                .trim()
                .split('\n')
                .map(
                    line => line.split('|').map(elem => elem.trim())
                )

            // transform data into array of objects using first element as title
            let title = data.shift();
            let res = data.map(line => {
                let res = {};
                line.forEach((elem, i) => res[BGP_TITLES[title[i]]] = elem);
                return res;
            });

            // take first line from answer
            resolve(res[0]);
        })

        // send command
        .end(BGP_WHOIS_CMD.replace('${host}', host));
    });
}


/**
 * Try to get all possible info about domain name or IP-address.
 *
 * @param string host Domain name or IP-address.
 * @return object Promise where `then()` has the following object as parameter:
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
const hostInfo = (host) => {
    return new Promise((resolve, reject) => {
        // result skeleton
        let result = {
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

            /*
             we need the following pattern to convert our Promises into
             ones that always resolves (on reject it just resolves with
             null as callback parameter):
             new Promise(r => func(host).then(info => r(info)).catch(err => r(null)))
            */
            Promise.all(
                [reverse, geoInfo, torInfo, bgpInfo, whois]
                .map(fn => new Promise(r => fn(host).then(info => r(info)).catch(err => r(null))))
            )
            .then(info => {
                result.reverse = info[0];
                result.geoInfo = info[1];
                result.torInfo = info[2];
                result.bgpInfo = info[3];
                result.whois   = info[4];

                resolve(result);
            })

        // collect available info about domain
        } else {
            result.isIP     = false;
            result.isDomain = true;

            Promise.all(
                [nslookup, whois]
                .map(fn => new Promise(r => fn(host).then(info => r(info)).catch(err => r(null))))
            )
            .then(info => {
                result.nslookup = info[0];
                result.whois    = info[1];

                resolve(result);
            })
        }
    });
}


exports.ip2long      = ip2long;
exports.isIP         = isIP;
exports.isDomain     = isDomain;
exports.reverse      = reverse;
exports.nslookup     = nslookup;
exports.whois        = whois;
exports.torInfo      = torInfo;
exports.extractIP    = extractIP;
exports.extractIPGen = extractIPGen;
exports.geoInit      = geoInit;
exports.geoInfo      = geoInfo;
exports.bgpInfo      = bgpInfo;
exports.hostInfo     = hostInfo;
