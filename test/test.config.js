/*
 * Copyright (c) 2017 Digital Bazaar, Inc. All rights reserved.
 */

const config = require('bedrock').config;
const path = require('path');

console.log('ZZZZZZZZZZZZZZZZZZZZZZZZZZZ');
config.mocha.tests.push(path.join(__dirname, 'mocha'));
