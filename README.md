# Description

Library can get various network information about domain names and IP-addresses.

Currently it provides the following information:
- whois (currently using [node-whois](https://github.com/hjr265/node-whois) library)
- BGP information (AS number and name)
- define whether IP address is TOR node either exit node, or entry node, or other
- DNS information
- GeoLocation information simultaneously using MaxMind and IP2Location databases

# Installation

You can install it with this command:
```bash
npm install node-xwhois
```


# Usage

Simplest way to get all possible information about domain name or IP address is using `hostInfo()` function:

```JavaScript
'use strict'
const whois = require('node-xwhois');

const host1 = 'xinit.ru';
const host2 = '8.8.8.8';

whois.geoInit('test/GeoIP')
.then(() => {
    whois.hostInfo(host1)
    .then(data => console.log(`${host1} info:\n`, JSON.stringify(data, null, 4)))
    .catch(err => console.log(err));

    whois.hostInfo(host2)
    .then(data => console.log(`${host2} info:\n`, JSON.stringify(data, null, 4)))
    .catch(err => console.log(err));
})
.catch(err => console.log(err));
```

All asynchronous functions in this library return Promises.


# Documentation
- [ip2long](#ip2longip)
- [isIP](#isiphost)
- [isDomain](#isdomainhost)
- [reverse](#reverseip)
- [nslookup](#nslookuphost)
- [whois](#whoishost)
- [torInfo](#torinfoip)
- [extractIP](#extractipstr)
- [geoInit](#geoinitdbpath)
- [geoInfo](#geoinfohost)
- [geoUpdate](#geoupdatedbpath-token)
- [bgpInfo](#bgpinfohost)
- [info](#infohost)

## `ip2long(ip)`
A JavaScript equivalent of PHP's ip2long(). Convert IPv4 address in dotted notation to 32-bit long integer.
You can pass IP in all possible representations, i.e.:
```
192.0.34.166
0xC0.0x00.0x02.0xEB
0xC00002EB
3221226219
0.0xABCDEF
255.255.255.256
0300.0000.0002.0353
030000001353
```
### Parameters
**ip**
String. IPv4-address in one of possible representations.

### Return
32-bit number notation of IP-address expressed in decimal.

## `isIP(host)`
Detect if `host` is correct IP-address. Internally uses `net.isIP()`.

### Parameters
**host**
String to test.

### Return
`true` if `host` is correct IP address or `false` otherwise.

## `isDomain(host)`
Detect if host is correct domain name. It can't test IDN's. And it can't define if domain name is really exist or can exist. This function just performs syntax check.

### Parameters
**host**
String to test.

### Return
True if `host` is correct domain name false otherwise.

## `reverse(ip)`
Define domain names by IP-address using reverse domain request.

### Parameters
**ip**
IP-address to reverse.

### Return
Promise where `then()` takes function with array of hostnames.

### Example
```JavaScript
const host = '8.8.8.8';

whois.reverse(host)
.then(hostnames => console.log(`${host} reverse:\n`, JSON.stringify(hostnames, null, 4)))
.catch(err => console.log(err));
```

## `nslookup(host)`
Get host info of domain name like `host -a` command.

### Parameters
**host**
Domain name.

### Return
Promise where `then()` takes function with object like this:
```JavaScript
{
    'A'    : ['IPv4-addresses'],
    'AAAA' : ['IPv6-addresses'],
    'MX'   : ['MX-records'    ],
    'TXT'  : ['TXT-records'   ],
    'SRV'  : ['SRV-records'   ],
    'NS'   : ['NS-records'    ],
    'CNAME': ['CNAME-records' ],
    'SOA'  : ['SOA-records'   ]
}
```

### Example
```JavaScript
const host = 'xinit.co';

whois.nslookup(host)
.then(info => console.log(`${host} nslookup:\n`, JSON.stringify(info, null, 4)))
.catch(err => console.log(err));
```

## `whois(host)`
Perform whois request.

### Parameters
**host**
Domain name or IP-address.

### Return
Promise where `then()` takes function with whois text.

### Example
```JavaScript
const host = 'xinit.co';

whois.whois(host)
.then(info => console.log(`${host} whois:\n`, JSON.stringify(info, null, 4)))
.catch(err => console.log(err));
```

## `torInfo(ip)`
Check if IP address is a TOR node.

### Parameters
**ip**
IP-address.

### Return
Promise where `then()` takes function with object like this:
```JavaScript
{
    'nodename': 'Name of TOR node',
    'port'    : [0, 0],  // port numbers of TOR node
    'exitNode': true     // if true then this is exit node
}
```
If IP does not belong to TOR node then null will be passed instead of described object.

### Example
```JavaScript
const host = '199.87.154.255';

whois.torInfo(host)
.then(info => console.log(`${host} torInfo:\n`, JSON.stringify(info, null, 4)))
.catch(err => console.log(err));
```

## `extractIP(str)`
Extract IP-addresses from raw text. If some IP-address appears in `str` multiple times then it will be returned in answer only once.

### Parameters
**str**
String to extract IP-addresses from.

### Return
Promise where `then()` takes function with array of IP-addresses as strings.

### Example
```JavaScript
const ipStr = `
    test raw text test raw text
    77.109.141.140    (37.187.130.68)   ++   188.40.143.7   $$   95.174.227.96 test raw text
    test raw text test raw text test raw text test raw text
    2001:0db8:11a3:09d7:1f34:8a2e:07a0:765d    test raw text test raw text
    2001:0db8:0000:0000:0000:0000:ae21:ad12
    test raw text
    188.40.143.7 188.40.143.7
`;

whois.extractIP(ipStr)
.then(info => console.log('extractIP:\n', JSON.stringify(info, null, 4)))
.catch(err => console.log(err));
```

## `geoInit(dbPath)`
Initialize script to get GeoLocation information. You need to call this function before using `geoInfo()` or `hostInfo()`.

### Parameters
**dbPath**
Path to directory where GeoLocation DB-files located.

You need to download GeoLocation databases by yourself or using `geoUpdate()`.

If you will download it manually you should get following files:<br>
    `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb` from
    [MaxMind](https://www.maxmind.com/en/geoip2-databases)<br>
    `IP2LOCATION-LITE-DB5.IPV6.BIN` and `IP2PROXY-LITE-PX4.BIN` from
    [IP2Location](https://www.ip2location.com/database)

### Return
Promise without any parameters. Run `geoInfo()` only within `then()` of this
Promise to be sure that all GeoLocation DB properly loaded.


## `geoInfo(host)`
Get GeoLocation information.

### Parameters
**host**
IP address to get info about.

### Return
Promise where `then()` has object as parameter like in this example:
```JavaScript
{
    ip          : '78.46.112.219',
    asn         : '24940',
    as_org      : 'Hetzner Online GmbH',
    proxy       : 'VPN', // see https://www.ip2proxy.com/ for possible values
    country_code: ['DE'],
    country     : ['Germany'],
    region      : [ 'Bayern', 'Bavaria', 'Sachsen' ],
    city        : [ 'Nürnberg', 'Nuremberg', 'Falkenstein' ],
    country_ru  : 'Германия',
    region_ru   : 'Бавария',
    city_ru     : 'Нюрнберг',
    timezone    : 'Europe/Berlin',
    coords      : [
        { lat: 49.4478, lon: 11.068299999999994 },
        { lat: 49.4478, lon: 11.0683 }
    ]
}
```

### Example
```JavaScript
const host = '199.87.154.255';

whois.geoInit('test/GeoIP')
.then(() => {
    return whois.geoInfo(host);
})
.then(info => {
    console.log(`${host} geoInfo:\n`, info)
})
.catch(err => console.log(err));
```

## `geoUpdate(dbPath, token)`
Update MaxMind and IP2Location databases.

### Parameters
**dbPath**
Full local path to store DB files.

**token**
API token to download IP2Location database. You should register on https://www.ip2location.com/ to get it.

### Return
Promise without any parameters.

### Example
```JavaScript
const path  = './GeoIP';
const token = 'insert your token here';

whois.geoUpdate(path, token)
.then(() => {
    console.log('OK');
})
.catch(err => {
    console.log('ERROR');
    console.log(err);
});
```


## `bgpInfo(host)`
Get BGP information, such as Autonomous System number. You can get this info manually by using this command in Linux console:
```bash
$ echo "-c -r -a -u -p 109.111.139.45" | nc whois.cymru.com 43
```

### Parameters
**host**
IP address to get info about.

### Return
Promise with array of the following objects in `then()`:
```JavaScript
[{
    "as": "18451",
    "ip": "199.87.154.255",
    "prefix": "199.87.152.0/21",
    "country_code": "CA",
    "registry": "arin",
    "allocation_date": "2011-01-31",
    "name": "ASN-LES - LES.NET,CA"
}]
```

### Example
```JavaScript
const host = '199.87.154.255';

whois.bgpInfo(host)
.then(info => console.log(`${host} bgpInfo:\n`, JSON.stringify(info, null, 4)))
.catch(err => console.log(err));
```

## `info(host)`
Get all possible information about domain name or IP-address.

### Parameters
**host**
Domain name or IP-address.

### Return
Promise where `then()` has the following object as parameter:
```JavaScript
{
    host    : host,
    isIP    : true,
    longIP  : null,
    reverse : null,
    geoInfo : null,
    torInfo : null,
    bgpInfo : null,
    isDomain: false,
    nslookup: null,
    whois   : null
}
```

### Example
```JavaScript
const host1 = 'xinit.co';
const host2 = '8.8.8.8';

whois.geoInit('test/GeoIP')
.then(() => {
    whois.info(host1)
    .then(data => console.log(`${host1} info:\n`, JSON.stringify(data, null, 4)))
    .catch(err => console.log(err));

    whois.info(host2)
    .then(data => console.log(`${host2} info:\n`, JSON.stringify(data, null, 4)))
    .catch(err => console.log(err));
})
.catch(err => console.log(err));
```


***

@license MIT<br>
@version 2.0.10<br>
@author Alexander Russkiy <developer@xinit.ru>
