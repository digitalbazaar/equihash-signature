/*!
 * Copyright (c) 2017 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const async = require('async');
const bedrock = require('bedrock');
const crypto = require('crypto');
const equihash = require('equihash')('khovratovich');
const jsonld = bedrock.jsonld;

const api = {};
// NOTE: only exported for tests
module.exports = api;

// FIXME: deal with docs that already have signatures
api.sign = (options, callback) => {
  async.auto({
    normalize: callback => jsonld.normalize(options.doc, {
      algorithm: 'URDNA2015',
      format: 'application/nquads'
    }, callback),
    proof: ['normalize', (results, callback) => {
      const hash =
        crypto.createHash('sha256').update(results.normalize, 'utf8').digest();
      const equihashOptions = {
        n: options.n,
        k: options.k
      };
      equihash.solve(hash, equihashOptions, callback);
    }],
    sign: ['proof', (results, callback) => {
      const signed = bedrock.util.clone(options.doc);
      signed.signature = {
        type: 'EquihashSignature2017',
        equihashParameterN: results.proof.n,
        equihashParameterK: results.proof.k,
        nonce: results.proof.nonce,
        signatureValue: Buffer.from(results.proof.value).toString('base64')
      };
      callback(null, signed);
    }]
  }, (err, results) => {
    if(err) {
      return callback(err);
    }
    callback(null, results.sign);
  });
};

api.verify = function(document, callback) {

  const unsignedDocument = bedrock.util.clone(document);
  const signature = unsignedDocument.signature;
  delete unsignedDocument.signature;

  async.auto({
    normalize: callback => bedrock.jsonld.normalize(unsignedDocument, {
      algorithm: 'URDNA2015',
      format: 'application/nquads'
    }, callback),
    verify: ['normalize', (results, callback) => {
      const hash =
        crypto.createHash('sha256').update(results.normalize, 'utf8').digest();
      const equihashOptions = {
        n: signature.equihashParameterN,
        k: signature.equihashParameterK,
        nonce: signature.nonce,
        value: Buffer.from(signature.signatureValue, 'base64')
      };
      callback(null, equihash.verify(hash, equihashOptions));
    }]
  }, (err, results) => {
    if(err) {
      return callback(err);
    }
    callback(null, results.verify);
  });
};
