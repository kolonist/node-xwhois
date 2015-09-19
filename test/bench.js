'use strict'
/**
 * Benchmark of extractIP() and extractIPGen().
 */
const path   = require('path');
const fs     = require('fs');


// require lib
const whois = require('./../lib/whois');


// test vectors
const testVectors = [
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
      `
    , fs.readFileSync(path.join('test', 'extractIP_test', '1.txt'), {encoding: 'utf8'})
    , fs.readFileSync(path.join('test', 'extractIP_test', '2.txt'), {encoding: 'utf8'})
    , fs.readFileSync(path.join('test', 'extractIP_test', '3.txt'), {encoding: 'utf8'})
    , fs.readFileSync(path.join('test', 'extractIP_test', '4.txt'), {encoding: 'utf8'})
];


/* extractIPGen() */
const testExtractIPGen = () => new Promise((resolve) => {
    let timeStart = process.hrtime();

    testVectors.forEach(str => {
        let extractIPGen = whois.extractIPGen(str);

        let ip;
        while (null !== (ip = extractIPGen.next().value));
    });

    let timeEnd = process.hrtime(timeStart);
    console.log('extractIPGen()', timeEnd[0] * 1e9 + timeEnd[1]);

    resolve();
});


/* extractIP() */
const testExtractIP = () => new Promise((resolve) => {
    let timeStart = process.hrtime();

    Promise.all(
        testVectors.map(str => whois.extractIP(str))
    )
    .then(data => {
        let timeEnd = process.hrtime(timeStart);
        console.log('extractIP()   ', timeEnd[0] * 1e9 + timeEnd[1]);

        resolve();
    })
    .catch(err => console.log('Error in "extractIP()":', err));
});


Promise.resolve(true)

.then(() => testExtractIPGen())
.then(() => testExtractIPGen())
.then(() => testExtractIPGen())
.then(() => testExtractIPGen())
.then(() => testExtractIPGen())
.then(() => testExtractIPGen())

.then(() => testExtractIP())
.then(() => testExtractIP())
.then(() => testExtractIP())
.then(() => testExtractIP())
.then(() => testExtractIP())
.then(() => testExtractIP())

.then(() => testExtractIPGen())
.then(() => testExtractIP())
.then(() => testExtractIP())
.then(() => testExtractIPGen())
.then(() => testExtractIPGen())
.then(() => testExtractIP())
.then(() => testExtractIPGen())
.then(() => testExtractIP())
