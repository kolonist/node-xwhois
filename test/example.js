'use strict'
//const whois = require('node-xwhois');
const whois = require('./../lib/whois');

const host1 = 'xinit.co';
const host2 = '8.8.8.8';
const host3 = '199.87.154.255';
const ipStr = `
    test raw text test raw text
    77.109.141.140    (37.187.130.68)   ++   188.40.143.7   $$   95.174.227.96 test raw text
    test raw text test raw text test raw text test raw text
    2001:0db8:11a3:09d7:1f34:8a2e:07a0:765d    test raw text test raw text
    2001:0db8:0000:0000:0000:0000:ae21:ad12
    test raw text
    188.40.143.7 188.40.143.7
`;


whois.reverse(host2)
.then(hostnames => console.log(`${host2} reverse:\n`, JSON.stringify(hostnames, null, 4)))
.catch(err => console.log(err));


whois.nslookup(host1)
.then(info => console.log(`${host1} nslookup:\n`, JSON.stringify(info, null, 4)))
.catch(err => console.log(err));


whois.whois(host1)
.then(info => console.log(`${host1} whois:\n`, info))
.catch(err => console.log(err));


whois.torInfo(host3)
.then(info => console.log(`${host3} torInfo:\n`, info))
.catch(err => console.log(err));


whois.extractIP(ipStr)
.then(info => console.log('extractIP:\n', JSON.stringify(info, null, 4)))
.catch(err => console.log(err));


const extractIPGen = whois.extractIPGen(ipStr);
let ip;
while (undefined !== (ip = extractIPGen.next().value))
    console.log('extractIPGen:', ip);


whois.bgpInfo(host3)
.then(info => console.log(`${host3} bgpInfo:\n`, JSON.stringify(info, null, 4)))
.catch(err => console.log(err));


whois.geoInit('test/GeoIP', {
    ip2location: {
        db    : 'ip2location.bin',
        source: ['IP2LOCATION-LITE-DB5.IPV6.BIN', 'IP2LOCATION-LITE-DB5.BIN']
    },
    maxMind  : {city: 'GeoLiteCity.dat',   org: 'GeoIPASNum.dat'  },
    maxMindv6: {city: 'GeoLiteCityv6.dat', org: 'GeoIPASNumv6.dat'},
    maxMind2 : 'GeoLite2-City.mmdb'
})
.then(() => {
    whois.geoInfo(host3)
    .then(info => console.log(`${host3} geoInfo:\n`, info))
    .catch(err => console.log(err));

    whois.hostInfo(host1)
    .then(data => console.log(`${host1} info:\n`, JSON.stringify(data, null, 4)))
    .catch(err => console.log(err));

    whois.hostInfo(host2)
    .then(data => console.log(`${host2} info:\n`, JSON.stringify(data, null, 4)))
    .catch(err => console.log(err));
})
.catch(err => console.log(err));
