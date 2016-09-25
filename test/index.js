'use strict'
const assert = require('assert');
const util   = require('util');
const path   = require('path');
const fs     = require('fs');


// assertion
//const log = (name, ...args) => {
const log = function (comment, obj, ...args) {
    // output error message
    console.log(
        `Assertion Error in '${comment}':\n`,
        util.inspect(obj),
        '\n'
    );

    if (args.length > 0) {
        console.log(
            '\nAdditional parameters:\n',
            args.join('\n'),
            '\n'
        );
    }

    process.exit(1);
}


// require lib
const whois = require('./../lib/whois');


/* ip2long() */
console.log('ip2long()');
assert.equal(whois.ip2long('192.0.34.166'), 3221234342, '192.0.34.166 -> 3221234342');
assert.equal(whois.ip2long('0xC0.0x00.0x02.0xEB'), 3221226219, '0xC0.0x00.0x02.0xEB -> 3221226219');
assert.equal(whois.ip2long('0xC00002EB'), 3221226219, '0xC00002EB -> 3221226219');
assert.equal(whois.ip2long('3221226219'), 3221226219, '3221226219 -> 3221226219');
assert.equal(whois.ip2long('0.0xABCDEF'), 11259375, '0.0xABCDEF -> 11259375');
assert.equal(whois.ip2long('0300.0000.0002.0353'), 3221226219, '0300.0000.0002.0353 -> 3221226219');
assert.equal(whois.ip2long('030000001353'), 3221226219, '030000001353 -> 3221226219');
assert.equal(whois.ip2long('255.255.255.256'), false, '255.255.255.256 -> false');
console.log('OK\n');


/* isIP() v4 */
console.log('isIP() v4');
assert.equal(whois.isIP('192.0.34.166'), true, '192.0.34.166 -> true');
assert.equal(whois.isIP('192.168.4.114.xip.io'), false, '192.168.4.114.xip.io -> false');
assert.equal(whois.isIP('3221234342'), false, '3221234342 -> false');
assert.equal(whois.isIP('0.0xABCDEF'), false, '0.0xABCDEF -> false');
assert.equal(whois.isIP('255.255.255.256'), false, '255.255.255.256 -> false');
console.log('OK\n');


/* isIP() v6 */
console.log('isIP() v6');
assert.equal(whois.isIP('2000::'), true, '2000:: -> true');
assert.equal(whois.isIP('3FFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF'), true, '3FFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF -> true');
assert.equal(whois.isIP('2001:0db8:11a3:09d7:1f34:8a2e:07a0:765d'), true, '2001:0db8:11a3:09d7:1f34:8a2e:07a0:765d -> true');
assert.equal(whois.isIP('2001:0db8:0000:0000:0000:0000:ae21:ad12'), true, '2001:0db8:0000:0000:0000:0000:ae21:ad12 -> true');
assert.equal(whois.isIP('2001:db8::ae21:ad12'), true, '2001:db8::ae21:ad12 -> true');
assert.equal(whois.isIP('0000:0000:0000:0000:0000:0000:ae21:ad12'), true, '0000:0000:0000:0000:0000:0000:ae21:ad12 -> true');
assert.equal(whois.isIP('::aq21:ad12'), false, '::aq21:ad12 -> false');
assert.equal(whois.isIP('ad12'), false, 'ad12 -> false');
console.log('OK\n');


/* isDomain() */
console.log('isDomain()');
assert.equal(whois.isDomain('xinit.ru'), true, 'xinit.ru -> true');
assert.equal(whois.isDomain('xinit.ru.'), true, 'xinit.ru. -> true');
assert.equal(whois.isDomain('xinit.russia'), true, 'xinit.russia -> true');
assert.equal(whois.isDomain('xin-it.co'), true, 'xin-it.co -> true');
assert.equal(whois.isDomain('xin--it.co'), true, 'xin--it.co -> true');
assert.equal(whois.isDomain('4012.ru'), true, '4012.ru -> true');
assert.equal(whois.isDomain('пример.рф'), true, 'пример.рф -> true');
assert.equal(whois.isDomain('пример.su'), true, 'пример.su -> true');
assert.equal(whois.isDomain('www.xinit.ru'), true, 'www.xinit.ru -> true');
assert.equal(whois.isDomain('ввв.xinit.ru'), true, 'ввв.xinit.ru -> true');
assert.equal(whois.isDomain('xinit.рф'), true, 'xinit.рф -> true');
assert.equal(whois.isDomain('127.0.0.1.ru'), true, '127.0.0.1.ru -> true');
assert.equal(whois.isDomain('s.xinit.ru'), true, 's.xinit.ru -> true');
assert.equal(whois.isDomain('XN--80ABERRY5A.XN--P1AI'), true, 'XN--80ABERRY5A.XN--P1AI -> true');
assert.equal(whois.isDomain('.'), false, '. -> false');
assert.equal(whois.isDomain('0.r'), false, '0.r -> false');
assert.equal(whois.isDomain('example.0'), false, 'example.0 -> false');
assert.equal(whois.isDomain('example.01'), false, 'example.01 -> false');
assert.equal(whois.isDomain('01.02'), false, '01.02 -> false');
assert.equal(whois.isDomain('-ex.ru'), false, '-ex.ru -> false');
assert.equal(whois.isDomain('ex-.ru'), false, 'ex-.ru -> false');
assert.equal(whois.isDomain('127.0.0.1'), false, '127.0.0.1 -> false');
assert.equal(whois.isDomain('ru'), false, 'ru -> false');
assert.equal(whois.isDomain('ru.'), false, 'ru. -> false');
assert.equal(whois.isDomain('.ru.'), false, '.ru. -> false');
assert.equal(whois.isDomain('.ru'), false, '.ru -> false');
assert.equal(whois.isDomain('.xinit.ru'), false, '.xinit.ru -> false');
assert.equal(whois.isDomain('s..xinit.ru'), false, 's..xinit.ru -> false');
console.log('OK\n');


/* reverse() */
console.log('reverse()');
whois.reverse('5.135.189.181' ).then(hostnames => { if (!Array.isArray(hostnames)) log('reverse()', hostnames) }).catch(err => log('reverse()', err));
whois.reverse('83.219.135.245').then(hostnames => { if (!Array.isArray(hostnames)) log('reverse()', hostnames) }).catch(err => log('reverse()', err));
whois.reverse('144.76.195.239').then(hostnames => { if (!Array.isArray(hostnames)) log('reverse()', hostnames) }).catch(err => log('reverse()', err));
whois.reverse('82.192.95.170' ).then(hostnames => { if (!Array.isArray(hostnames)) log('reverse()', hostnames) }).catch(err => log('reverse()', err));
whois.reverse('77.88.55.66'   ).then(hostnames => { if (!Array.isArray(hostnames)) log('reverse()', hostnames) }).catch(err => log('reverse()', err));
whois.reverse('127.0.0.1'     ).then(hostnames => { if (!Array.isArray(hostnames)) log('reverse()', hostnames) }).catch(err => log('reverse()', err));
whois.reverse('xinit.ru'      ).then(hostnames => { if (Array.isArray(hostnames)) log('reverse()', hostnames) }).catch(err => { if (typeof err !== 'object') log('reverse()', err) });
whois.reverse('ip'            ).then(hostnames => { if (Array.isArray(hostnames)) log('reverse()', hostnames) }).catch(err => { if (typeof err !== 'object') log('reverse()', err) });
console.log('OK\n');


/* nslookup() */
console.log('nslookup()');
whois.nslookup('xinit.ru'               ).then(addresses => { if (typeof addresses !== 'object') log('nslookup()', addresses) }).catch(err => log('nslookup()', err));
whois.nslookup('google.com'             ).then(addresses => { if (typeof addresses !== 'object') log('nslookup()', addresses) }).catch(err => log('nslookup()', err));
whois.nslookup('yandex.ru'              ).then(addresses => { if (typeof addresses !== 'object') log('nslookup()', addresses) }).catch(err => log('nslookup()', err));
whois.nslookup('habr.ru'                ).then(addresses => { if (typeof addresses !== 'object') log('nslookup()', addresses) }).catch(err => log('nslookup()', err));
whois.nslookup('vk.com'                 ).then(addresses => { if (typeof addresses !== 'object') log('nslookup()', addresses) }).catch(err => log('nslookup()', err));
whois.nslookup('зубаков.рф'             ).then(addresses => { if (typeof addresses !== 'object') log('nslookup()', addresses) }).catch(err => log('nslookup()', err));
whois.nslookup('XN--80ABERRY5A.XN--P1AI').then(addresses => { if (typeof addresses !== 'object') log('nslookup()', addresses) }).catch(err => log('nslookup()', err));
whois.nslookup('пример.su'              ).then(addresses => { if (typeof addresses !== 'object') log('nslookup()', addresses) }).catch(err => log('nslookup()', err));
whois.nslookup('xinit.рф'               ).then(addresses => { if (typeof addresses !== 'object') log('nslookup()', addresses) }).catch(err => log('nslookup()', err));
whois.nslookup('83.219.135.207'         ).then(addresses => { if (typeof addresses !== 'object') log('nslookup()', addresses) }).catch(err => { if (typeof err !== 'object') log('nslookup()', err) });
console.log('OK\n');


/* whois() */
console.log('whois()');
whois.whois('xinit.ru'               ).then(data => { if (data === '') log('whois()', data) }).catch(err => log('whois()', err));
whois.whois('google.com'             ).then(data => { if (data === '') log('whois()', data) }).catch(err => log('whois()', err));
whois.whois('yandex.ru'              ).then(data => { if (data === '') log('whois()', data) }).catch(err => log('whois()', err));
whois.whois('habr.ru'                ).then(data => { if (data === '') log('whois()', data) }).catch(err => log('whois()', err));
whois.whois('vk.com'                 ).then(data => { if (data === '') log('whois()', data) }).catch(err => log('whois()', err));
whois.whois('зубаков.рф'             ).then(data => { if (data === '') log('whois()', data) }).catch(err => log('whois()', err));
whois.whois('XN--80ABERRY5A.XN--P1AI').then(data => { if (data === '') log('whois()', data) }).catch(err => log('whois()', err));
whois.whois('xn--80aberry5a.xn--p1ai').then(data => { if (data === '') log('whois()', data) }).catch(err => log('whois()', err));
whois.whois('пример.su'              ).then(data => { if (data === '') log('whois()', data) }).catch(err => log('whois()', err));
whois.whois('xinit.рф'               ).then(data => { if (data === '') log('whois()', data) }).catch(err => log('whois()', err));
whois.whois('83.219.135.207'         ).then(data => { if (data === '') log('whois()', data) }).catch(err => log('whois()', err));
whois.whois('83.219.135.307'         ).then(data => { if (data === '') log('whois()', data) }).catch(err => log('whois()', err));
whois.whois(''                       ).then(data => { if (data === '') log('whois()', data) }).catch(err => log('whois()', err));
whois.whois(' '                      ).then(data => { if (data === '') log('whois()', data) }).catch(err => log('whois()', err));
whois.whois(1                        ).then(data => { if (data !== '') log('whois()', data) }).catch(err => {if (typeof err !== 'object') log('whois()', err) });
console.log('OK\n');


/* torInfo() */
console.log('torInfo()');

let testVectors = [
    {ip: '178.32.181.96'  , isIP: true,  isTOR: true },
    {ip: '94.242.246.23'  , isIP: true,  isTOR: true },
    {ip: '94.242.246.24'  , isIP: true,  isTOR: true },
    {ip: '89.163.237.45'  , isIP: true,  isTOR: true },
    {ip: '104.131.65.225' , isIP: true,  isTOR: true },

    {ip: '162.243.123.220', isIP: true,  isTOR: false},
    {ip: '23.80.226.4'    , isIP: true,  isTOR: false},
    {ip: '130.253.21.123' , isIP: true,  isTOR: false},
    {ip: '188.138.88.168' , isIP: true,  isTOR: false},
    {ip: '8.8.8.8'        , isIP: true,  isTOR: false},
    {ip: '8.8.4.4'        , isIP: true,  isTOR: false},
    {ip: '127.0.0.1'      , isIP: true,  isTOR: false},
    {ip: '5.135.189.181'  , isIP: true,  isTOR: false},

    {ip: 'xinit.ru'       , isIP: false, isTOR: false},
    {ip: 'example.com'    , isIP: false, isTOR: false},
    {ip: 'test string'    , isIP: false, isTOR: false},
    {ip: ''               , isIP: false, isTOR: false},
    {ip: 0                , isIP: false, isTOR: false}
];

testVectors.forEach(test => {
    whois.torInfo(test.ip)
    .then(data => {
        if (test.isTOR && data === null)
            log('torInfo()', data);

        else if (!test.isTOR && data !== null)
            log('torInfo()', data);
    })
    .catch(err => {
        if (
               ( test.isIP && err !== null)
            || (!test.isIP && (typeof err !== 'object'))
        )
            log('torInfo()', err);
    });
});

console.log('OK\n');


/* extractIPGen() */
console.log('extractIPGen()');

testVectors = [
    `
    77.109.141.140    37.187.130.68      188.40.143.7      95.174.227.96
    5.135.155.121     127.0.0.1          83.219.135.207    1270.0.0.1
    103.21.244.0/22   103.22.200.0/22    103.31.4.0/22     104.16.0.0/12
    108.162.192.0/18  141.101.64.0/18    162.158.0.0/15    172.64.0.0/13
    173.245.48.0/20   188.114.96.0/20    190.93.240.0/20   197.234.240.0/22
    198.41.128.0/17   199.27.128.0/21
    2000::                                     3FFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF
    2001:0db8:11a3:09d7:1f34:8a2e:07a0:765d    2001:0db8:0000:0000:0000:0000:ae21:ad12
    2001:db8::ae21:ad12                        0000:0000:0000:0000:0000:0000:ae21:ad12
    2400:cb00::/32                             2405:8100::/32
    2405:b500::/32                             2606:4700::/32
    2803:f800::/32
    `,
     fs.readFileSync(path.join('test', 'extractIP_test', '1.txt'), {encoding: 'utf8'}),
     fs.readFileSync(path.join('test', 'extractIP_test', '2.txt'), {encoding: 'utf8'}),
     fs.readFileSync(path.join('test', 'extractIP_test', '3.txt'), {encoding: 'utf8'}),
     fs.readFileSync(path.join('test', 'extractIP_test', '4.txt'), {encoding: 'utf8'})
];

testVectors.forEach(str => {
    let extractIPGen = whois.extractIPGen(str);

    let ip;
    while (undefined !== (ip = extractIPGen.next().value))
        assert.equal(typeof ip, 'string', 'extractIPGen() returns not IP');
});

console.log('OK\n');


/* extractIP() */
console.log('extractIP()');

testVectors = [
    `
    77.109.141.140    37.187.130.68      188.40.143.7      95.174.227.96
    5.135.155.121     127.0.0.1          83.219.135.207    1270.0.0.1
    103.21.244.0/22   103.22.200.0/22    103.31.4.0/22     104.16.0.0/12
    108.162.192.0/18  141.101.64.0/18    162.158.0.0/15    172.64.0.0/13
    173.245.48.0/20   188.114.96.0/20    190.93.240.0/20   197.234.240.0/22
    198.41.128.0/17   199.27.128.0/21
    2000::                                     3FFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF
    2001:0db8:11a3:09d7:1f34:8a2e:07a0:765d    2001:0db8:0000:0000:0000:0000:ae21:ad12
    2001:db8::ae21:ad12                        0000:0000:0000:0000:0000:0000:ae21:ad12
    2400:cb00::/32                             2405:8100::/32
    2405:b500::/32                             2606:4700::/32
    2803:f800::/32
    `,
     fs.readFileSync(path.join('test', 'extractIP_test', '1.txt'), {encoding: 'utf8'}),
     fs.readFileSync(path.join('test', 'extractIP_test', '2.txt'), {encoding: 'utf8'}),
     fs.readFileSync(path.join('test', 'extractIP_test', '3.txt'), {encoding: 'utf8'}),
     fs.readFileSync(path.join('test', 'extractIP_test', '4.txt'), {encoding: 'utf8'})
];

testVectors.forEach(str => {
    whois.extractIP(str).then(data => { if (!Array.isArray(data) || data.length <= 0) log('extractIP()', data) }).catch(err => log('extractIP()', err));
});

console.log('OK\n');


/* geoInfo() */
console.log('geoInfo()');

let geoInitialization = whois.geoInit(path.join('test', 'GeoIP'), {
    ip2location: {
        db    : 'ip2location.bin',
        source: ['IP2LOCATION-LITE-DB5.IPV6.BIN', 'IP2LOCATION-LITE-DB5.BIN']
    },
    maxMind  : {city: 'GeoLiteCity.dat',   org: 'GeoIPASNum.dat'  },
    maxMindv6: {city: 'GeoLiteCityv6.dat', org: 'GeoIPASNumv6.dat'},
    maxMind2 : 'GeoLite2-City.mmdb'
});

geoInitialization.then(() => {
    let testVectors = [
          '121.200.103.190',
         '109.111.139.45',
         '77.109.141.140',
         '127.0.0.1',
         '37.187.130.68',
         '121.69.113.7',
         '124.53.86.188',
         '83.167.112.7',
         '91.76.97.133',
         '212.154.238.181',
         '201.11.139.220',
         '200.3.223.231',
         '107.170.65.197',
         '195.154.215.240',
         '78.46.112.219',
         '37.60.214.34',
         '5.135.189.181',
         '93.228.75.194',
         'fc00:3::1200:ff:fe00:1',
         '2001:0db8:11a3:09d7:1f34:8a2e:07a0:765d',
         '2001:41d0:8:c6b5::1'
    ];

    testVectors.forEach(host => {
        whois.geoInfo(host).then(data => { if (data === null) log('geoInfo()', data) }).catch(err => log('geoInfo()', err));
    });
})
.catch(err => log('geoIPInit()', err));

console.log('OK\n');


/* bgpInfo() */
console.log('bgpInfo()');

testVectors = [
      '121.200.103.190',
     '109.111.139.45',
     '77.109.141.140',
     '127.0.0.1',
     '37.187.130.68',
     '121.69.113.7',
     '124.53.86.188',
     '83.167.112.7',
     '91.76.97.133',
     '212.154.238.181',
     '201.11.139.220',
     '200.3.223.231',
     '107.170.65.197',
     '195.154.215.240',
     '78.46.112.219',
     '37.60.214.34',
     '5.135.189.181',
     '93.228.75.194',
     'fc00:3::1200:ff:fe00:1',
     '2001:0db8:11a3:09d7:1f34:8a2e:07a0:765d',
     '2001:41d0:8:c6b5::1'
];

testVectors.forEach(host => {
    whois.bgpInfo(host).then(data => { if (data === null) log('bgpInfo()', data) }).catch(err => log('bgpInfo()', err));
});

console.log('OK\n');


/* hostInfo() */
console.log('hostInfo()');

geoInitialization.then(() => {
    testVectors = [
          '121.200.103.190',
         '162.243.123.220',
         '5.135.189.181',
         '127.0.0.1',
         'xinit.ru',
         'yandex.ru',
         '2001:0db8:11a3:09d7:1f34:8a2e:07a0:765d'
    ];

    testVectors.forEach(host => {
        whois.hostInfo(host).then(data => { if (data === null) log(hostInfo(), data) }).catch(err => log('hostInfo()', err));
    });
});

console.log('OK\n');
