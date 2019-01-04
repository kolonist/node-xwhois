'use strict'

const path   = require('path');


// require lib
const whois = require('./../lib/whois');

const local_path = path.join(__dirname, 'GeoIP');
const token      = require('./token.json');

whois.geoUpdate(local_path, token)
.then(() => {
    console.log('OK');
    console.log();
})
.catch(err => {
    console.log('ERROR');
    console.log(err);
});
