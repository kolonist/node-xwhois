'use strict'
const assert = require('assert');
const path   = require('path');
const fs     = require('fs');


// require lib
const whois = require('./../lib/whois');


describe('ip2long()', () => {
    it('should convert 192.0.34.166 to 3221234342', done => {
        assert.equal(whois.ip2long('192.0.34.166'), 3221234342);
        done();
    });
    it('should convert 0xC0.0x00.0x02.0xEB to 3221226219', done => {
        assert.equal(whois.ip2long('0xC0.0x00.0x02.0xEB'), 3221226219);
        done();
    });
    it('should convert 0xC00002EB to 3221226219', done => {
        assert.equal(whois.ip2long('0xC00002EB'), 3221226219);
        done();
    });
    it('should convert 3221226219 to 3221226219', done => {
        assert.equal(whois.ip2long('3221226219'), 3221226219);
        done();
    });
    it('should convert 0.0xABCDEF to 11259375', done => {
        assert.equal(whois.ip2long('0.0xABCDEF'), 11259375);
        done();
    });
    it('should convert 0300.0000.0002.0353 to 3221226219', done => {
        assert.equal(whois.ip2long('0300.0000.0002.0353'), 3221226219);
        done();
    });
    it('should convert 030000001353 to 3221226219', done => {
        assert.equal(whois.ip2long('030000001353'), 3221226219);
        done();
    });
    it('should not convert 255.255.255.256', done => {
        assert.equal(whois.ip2long('255.255.255.256'), false);
        done();
    });
});

describe('isIP()', () => {
    it('should detect that 192.0.34.166 is IP', done => {
        assert.equal(whois.isIP('192.0.34.166'), true);
        done();
    });
    it('should detect that 2000:: is IP', done => {
        assert.equal(whois.isIP('2000::'), true);
        done();
    });
    it('should detect that 3FFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF is IP', done => {
        assert.equal(whois.isIP('3FFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF'), true);
        done();
    });
    it('should detect that 2001:0db8:11a3:09d7:1f34:8a2e:07a0:765d is IP', done => {
        assert.equal(whois.isIP('2001:0db8:11a3:09d7:1f34:8a2e:07a0:765d'), true);
        done();
    });
    it('should detect that 2001:0db8:0000:0000:0000:0000:ae21:ad12 is IP', done => {
        assert.equal(whois.isIP('2001:0db8:0000:0000:0000:0000:ae21:ad12'), true);
        done();
    });
    it('should detect that 2001:db8::ae21:ad12 is IP', done => {
        assert.equal(whois.isIP('2001:db8::ae21:ad12'), true);
        done();
    });
    it('should detect that 0000:0000:0000:0000:0000:0000:ae21:ad12 is IP', done => {
        assert.equal(whois.isIP('0000:0000:0000:0000:0000:0000:ae21:ad12'), true);
        done();
    });
    it('should detect that 192.168.4.114.xip.io is not IP', done => {
        assert.equal(whois.isIP('192.168.4.114.xip.io'), false);
        done();
    });
    it('should detect that 3221234342 is not IP', done => {
        assert.equal(whois.isIP('3221234342'), false);
        done();
    });
    it('should detect that 0.0xABCDEF is not IP', done => {
        assert.equal(whois.isIP('0.0xABCDEF'), false);
        done();
    });
    it('should detect that 255.255.255.256 is not IP', done => {
        assert.equal(whois.isIP('255.255.255.256'), false);
        done();
    });
    it('should detect that ::aq21:ad12 is not IP', done => {
        assert.equal(whois.isIP('::aq21:ad12'), false);
        done();
    });
    it('should detect that ad12 is not IP', done => {
        assert.equal(whois.isIP('ad12'), false);
        done();
    });
});


describe('isDomain()', () => {
    it('should detect that xinit.ru is domain name', done => {
        assert.equal(whois.isDomain('xinit.ru'), true);
        done();
    });
    it('should detect that xinit.ru. is domain name', done => {
        assert.equal(whois.isDomain('xinit.ru.'), true);
        done();
    });
    it('should detect that xinit.russia is domain name', done => {
        assert.equal(whois.isDomain('xinit.russia'), true);
        done();
    });
    it('should detect that xin-it.co is domain name', done => {
        assert.equal(whois.isDomain('xin-it.co'), true);
        done();
    });
    it('should detect that xin--it.co is domain name', done => {
        assert.equal(whois.isDomain('xin--it.co'), true);
        done();
    });
    it('should detect that 4012.ru is domain name', done => {
        assert.equal(whois.isDomain('4012.ru'), true);
        done();
    });
    it('should detect that пример.рф is domain name', done => {
        assert.equal(whois.isDomain('пример.рф'), true);
        done();
    });
    it('should detect that пример.su is domain name', done => {
        assert.equal(whois.isDomain('пример.su'), true);
        done();
    });
    it('should detect that www.xinit.ru is domain name', done => {
        assert.equal(whois.isDomain('www.xinit.ru'), true);
        done();
    });
    it('should detect that ввв.xinit.ru is domain name', done => {
        assert.equal(whois.isDomain('ввв.xinit.ru'), true);
        done();
    });
    it('should detect that xinit.рф is domain name', done => {
        assert.equal(whois.isDomain('xinit.рф'), true);
        done();
    });
    it('should detect that 127.0.0.1.ru is domain name', done => {
        assert.equal(whois.isDomain('127.0.0.1.ru'), true);
        done();
    });
    it('should detect that s.xinit.ru is domain name', done => {
        assert.equal(whois.isDomain('s.xinit.ru'), true);
        done();
    });
    it('should detect that XN--80ABERRY5A.XN--P1AI is domain name', done => {
        assert.equal(whois.isDomain('XN--80ABERRY5A.XN--P1AI'), true);
        done();
    });
    it('should detect that . is not domain name', done => {
        assert.equal(whois.isDomain('.'), false);
        done();
    });
    it('should detect that 0.r is not domain name', done => {
        assert.equal(whois.isDomain('0.r'), false);
        done();
    });
    it('should detect that example.0 is not domain name', done => {
        assert.equal(whois.isDomain('example.0'), false);
        done();
    });
    it('should detect that example.01 is not domain name', done => {
        assert.equal(whois.isDomain('example.01'), false);
        done();
    });
    it('should detect that 01.02 is not domain name', done => {
        assert.equal(whois.isDomain('01.02'), false);
        done();
    });
    it('should detect that -ex.ru is not domain name', done => {
        assert.equal(whois.isDomain('-ex.ru'), false);
        done();
    });
    it('should detect that ex-.ru is not domain name', done => {
        assert.equal(whois.isDomain('ex-.ru'), false);
        done();
    });
    it('should detect that 127.0.0.1 is not domain name', done => {
        assert.equal(whois.isDomain('127.0.0.1'), false);
        done();
    });
    it('should detect that ru is not domain name', done => {
        assert.equal(whois.isDomain('ru'), false);
        done();
    });
    it('should detect that ru. is not domain name', done => {
        assert.equal(whois.isDomain('ru.'), false);
        done();
    });
    it('should detect that .ru. is not domain name', done => {
        assert.equal(whois.isDomain('.ru.'), false);
        done();
    });
    it('should detect that .ru is domain not name', done => {
        assert.equal(whois.isDomain('.ru'), false);
        done();
    });
    it('should detect that .xinit.ru is not domain name', done => {
        assert.equal(whois.isDomain('.xinit.ru'), false);
        done();
    });
    it('should detect that s..xinit.ru is not domain name', done => {
        assert.equal(whois.isDomain('s..xinit.ru'), false);
        done();
    });
});


describe('reverse()', () => {
    it('should reverse 5.135.189.181', done => {
        whois.reverse('5.135.189.181')
        .then(hostnames => {
            assert.equal(Array.isArray(hostnames), true);
            done();
        })
        .catch(err => done(err));
    });
    it('should reverse 83.219.135.245', done => {
        whois.reverse('83.219.135.245')
        .then(hostnames => {
            assert.equal(Array.isArray(hostnames), true);
            done();
        })
        .catch(err => done(err));
    });
    it('should reverse 144.76.195.239', done => {
        whois.reverse('144.76.195.239')
        .then(hostnames => {
            assert.equal(Array.isArray(hostnames), true);
            done();
        })
        .catch(err => done(err));
    });
    it('should reverse 82.192.95.170', done => {
        whois.reverse('82.192.95.170')
        .then(hostnames => {
            assert.equal(Array.isArray(hostnames), true);
            done();
        })
        .catch(err => done(err));
    });
    it('should reverse 77.88.55.66', done => {
        whois.reverse('77.88.55.66')
        .then(hostnames => {
            assert.equal(Array.isArray(hostnames), true);
            done();
        })
        .catch(err => done(err));
    });
    it('should reverse 127.0.0.1', done => {
        whois.reverse('127.0.0.1')
        .then(hostnames => {
            assert.equal(Array.isArray(hostnames), true);
            done();
        })
        .catch(err => done(err));
    });
    it('should not reverse xinit.ru', done => {
        whois.reverse('xinit.ru')
        .then(hostnames => {
            done(new Error());
        })
        .catch(err => done());
    });
    it('should not reverse "ip"', done => {
        whois.reverse('ip')
        .then(hostnames => {
            done(new Error());
        })
        .catch(err => done());
    });
});


describe('nslookup()', function() {
    this.timeout(10000);

    it('should nslookup xinit.ru', done => {
        whois.nslookup('xinit.ru')
        .then(addresses => {
            assert.equal(typeof addresses, 'object');
            done();
        })
        .catch(err => done(err));
    });
    it('should nslookup google.com', done => {
        whois.nslookup('google.com')
        .then(addresses => {
            assert.equal(typeof addresses, 'object');
            done();
        })
        .catch(err => done(err));
    });
    it('should nslookup yandex.ru', done => {
        whois.nslookup('yandex.ru')
        .then(addresses => {
            assert.equal(typeof addresses, 'object');
            done();
        })
        .catch(err => done(err));
    });
    it('should nslookup habr.ru', done => {
        whois.nslookup('habr.ru')
        .then(addresses => {
            assert.equal(typeof addresses, 'object');
            done();
        })
        .catch(err => done(err));
    });
    it('should nslookup vk.com', done => {
        whois.nslookup('vk.com')
        .then(addresses => {
            assert.equal(typeof addresses, 'object');
            done();
        })
        .catch(err => done(err));
    });
    it('should nslookup зубаков.рф', done => {
        whois.nslookup('зубаков.рф')
        .then(addresses => {
            assert.equal(typeof addresses, 'object');
            done();
        })
        .catch(err => done(err));
    });
    it('should nslookup XN--80ABERRY5A.XN--P1AI', done => {
        whois.nslookup('XN--80ABERRY5A.XN--P1AI')
        .then(addresses => {
            assert.equal(typeof addresses, 'object');
            done();
        })
        .catch(err => done(err));
    });
    it('should nslookup пример.su', done => {
        whois.nslookup('пример.su')
        .then(addresses => {
            assert.equal(typeof addresses, 'object');
            done();
        })
        .catch(err => done(err));
    });
    it('should nslookup xinit.рф', done => {
        whois.nslookup('xinit.рф')
        .then(addresses => {
            assert.equal(typeof addresses, 'object');
            done();
        })
        .catch(err => done(err));
    });
    it('should not nslookup IP address 83.219.135.207', done => {
        whois.nslookup('83.219.135.207')
        .then(addresses => {
            done(new Error());
        })
        .catch(err => done());
    });
});


describe('whois()', () => {
    it('should whois xinit.ru', done => {
        whois.whois('xinit.ru')
        .then(data => {
            assert.notEqual(data, '');
            done();
        })
        .catch(err => done(err));
    });
    it('should whois google.com', done => {
        whois.whois('google.com')
        .then(data => {
            assert.notEqual(data, '');
            done();
        })
        .catch(err => done(err));
    });
    it('should whois yandex.ru', done => {
        whois.whois('yandex.ru')
        .then(data => {
            assert.notEqual(data, '');
            done();
        })
        .catch(err => done(err));
    });
    it('should whois habr.ru', done => {
        whois.whois('habr.ru')
        .then(data => {
            assert.notEqual(data, '');
            done();
        })
        .catch(err => done(err));
    });
    it('should whois vk.com', done => {
        whois.whois('vk.com')
        .then(data => {
            assert.notEqual(data, '');
            done();
        })
        .catch(err => done(err));
    });
    it('should whois зубаков.рф', done => {
        whois.whois('зубаков.рф')
        .then(data => {
            assert.notEqual(data, '');
            done();
        })
        .catch(err => done(err));
    });
    it('should whois XN--80ABERRY5A.XN--P1AI', done => {
        whois.whois('XN--80ABERRY5A.XN--P1AI')
        .then(data => {
            assert.notEqual(data, '');
            done();
        })
        .catch(err => done(err));
    });
    it('should whois xn--80aberry5a.xn--p1ai', done => {
        whois.whois('xn--80aberry5a.xn--p1ai')
        .then(data => {
            assert.notEqual(data, '');
            done();
        })
        .catch(err => done(err));
    });
    it('should whois пример.su', done => {
        whois.whois('пример.su')
        .then(data => {
            assert.notEqual(data, '');
            done();
        })
        .catch(err => done(err));
    });
    it('should whois xinit.рф', done => {
        whois.whois('xinit.рф')
        .then(data => {
            assert.notEqual(data, '');
            done();
        })
        .catch(err => done(err));
    });
    it('should whois 83.219.135.207', done => {
        whois.whois('83.219.135.207')
        .then(data => {
            assert.notEqual(data, '');
            done();
        })
        .catch(err => done(err));
    });
    it('should whois 83.219.135.307', done => {
        whois.whois('83.219.135.307')
        .then(data => {
            assert.notEqual(data, '');
            done();
        })
        .catch(err => done(err));
    });
    it('should whois 2001:0db8:11a3:09d7:1f34:8a2e:07a0:765d', done => {
        whois.whois('2001:0db8:11a3:09d7:1f34:8a2e:07a0:765d')
        .then(data => {
            assert.notEqual(data, '');
            done();
        })
        .catch(err => done(err));
    });
    it('should whois " "', done => {
        whois.whois(' ')
        .then(data => {
            assert.notEqual(data, '');
            done();
        })
        .catch(err => done(err));
    });
    it('should not whois "1"', done => {
        whois.whois(1)
        .then(data => {
            done(new Error());
        })
        .catch(err => done());
    });
});


describe('torInfo()', () => {
    const testVectors = [
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
        it(`should ${test.isTOR ? '' : 'not '}define '${test.ip}' as TOR node`, done => {
            whois.torInfo(test.ip)
            .then(data => {
                if (test.isTOR && data === null)
                    done(new Error('There should be some info about Tor node'));

                else if (!test.isTOR && data !== null)
                    done(new Error('There should not be any info about non-Tor node'));

                else
                    done();
            })
            .catch(err => {
                if (test.isIP)
                    done(new Error('Should not catch() on IP-addresses'));
                else
                    done();
            });
        });
    });
});


describe('extractIP()', function() {
    this.timeout(10000);

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
        `,
        fs.readFileSync(path.join('test', 'extractIP_test', '1.txt'), {encoding: 'utf8'}),
        fs.readFileSync(path.join('test', 'extractIP_test', '2.txt'), {encoding: 'utf8'}),
        fs.readFileSync(path.join('test', 'extractIP_test', '3.txt'), {encoding: 'utf8'}),
        fs.readFileSync(path.join('test', 'extractIP_test', '4.txt'), {encoding: 'utf8'})
    ];

    testVectors.forEach(str => {
        it(`should extract array of IP addresses from string of ${str.length} bytes`, done => {
            whois.extractIP(str)
            .then(data => {
                if (!Array.isArray(data) || data.length === 0)
                    done(new Error('There should not be empty IP list'));
                else
                    done();
            })
            .catch(err => done(err));
        });
    });
});


describe('geoInit()', function() {
    this.timeout(10000);

    it('should properly initialize Geo functions', done => {
        whois.geoInit(path.join('test', 'GeoIP'), {
            ip2location: {
                db    : 'ip2location.bin',
                source: ['IP2LOCATION-LITE-DB5.IPV6.BIN', 'IP2LOCATION-LITE-DB5.BIN']
            },
            maxMind  : {city: 'GeoLiteCity.dat',   org: 'GeoIPASNum.dat'  },
            maxMindv6: {city: 'GeoLiteCityv6.dat', org: 'GeoIPASNumv6.dat'},
            maxMind2 : 'GeoLite2-City.mmdb'
        })
        .then(() => {
            describe('geoInfo()', () => {
                const testVectors = [
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

                testVectors.forEach(ip => {
                    it(`should give Geo info for ${ip}`, done => {
                        whois.geoInfo(ip)
                        .then(data => {
                            if (data === null)
                                done(new Error('Should return some Geo info'));
                            else {
                                done();
                            }
                        })
                        .catch(err => done(err));
                    });
                });
            });
            done();
        })
        .catch(err => done(err));
    });
});


describe('bgpInfo()', function() {
    this.timeout(10000);

    const testVectors = [
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

    testVectors.forEach(ip => {
        it(`should give BGP info for ${ip}`, done => {
            whois.bgpInfo(ip)
            .then(data => {
                if (data === null)
                    done(new Error('Should return some BGP related info'));
                else
                    done();
            })
            .catch(err => done(err));
        });
    });
});


describe('geoInit()', function() {
    this.timeout(10000);

    const testVectors = [
        '121.200.103.190',
        '162.243.123.220',
        '5.135.189.181',
        '127.0.0.1',
        'xinit.ru',
        'yandex.ru',
        '2001:0db8:11a3:09d7:1f34:8a2e:07a0:765d'
    ];

    it('should properly initialize Geo functions', done => {
        whois.geoInit(path.join('test', 'GeoIP'), {
            ip2location: {
                db    : 'ip2location.bin',
                source: ['IP2LOCATION-LITE-DB5.IPV6.BIN', 'IP2LOCATION-LITE-DB5.BIN']
            },
            maxMind  : {city: 'GeoLiteCity.dat',   org: 'GeoIPASNum.dat'  },
            maxMindv6: {city: 'GeoLiteCityv6.dat', org: 'GeoIPASNumv6.dat'},
            maxMind2 : 'GeoLite2-City.mmdb'
        })
        .then(() => {
            describe('hostInfo()', () => {
                testVectors.forEach(host => {
                    it(`should give info for ${host}`, done => {
                        whois.hostInfo(host)
                        .then(data => {
                            if (data === null)
                                done(new Error('Should return some info'));
                            else
                                done();
                        })
                        .catch(err => done(err));
                    });
                });
            });
            done();
        })
        .catch(err => done(err));
    });
});
