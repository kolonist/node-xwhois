'use strict';
/**
 * Benchmark of bgpInfo().
 */

// require lib
const whois = require('./../lib/whois');

// test vectors
const testVectors = [
    '121.200.103.190',
    '83.219.135.224',
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


/* bgpInfo() */
const testBgpInfo = () => new Promise(resolve => {
    let timeStart = process.hrtime();

    Promise.all(
        testVectors.map(str => whois.bgpInfo(str))
    )
    .then(data => {
        let timeEnd = process.hrtime(timeStart);
        console.log('bgpInfo()   ', timeEnd[0] * 1e9 + timeEnd[1]);

        resolve();
    })
    .catch(err => console.log('Error in "bgpInfo()":', err));
});


Promise.resolve(true)

.then(() => testBgpInfo())
.then(() => testBgpInfo())
.then(() => testBgpInfo())
.then(() => testBgpInfo())
.then(() => testBgpInfo())
.then(() => testBgpInfo())
