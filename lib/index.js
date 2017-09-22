/*!
 * Copyright (c) 2017 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const async = require('async');
const bedrock = require('bedrock');
const crypto = require('crypto');
const equihash = require('equihash');
const jsonld = bedrock.jsonld;

const api = {};
// NOTE: only exported for tests
module.exports = api;

api.sign = (options, callback) => {
  // FIXME: deal with docs that already have signatures
  // FIXME: compact before accessing 'signature' alias
  if(options.doc.signature) {
    return callback(
      new TypeError('Signing a document with a signature not yet supported.'));
  }

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
        k: options.k,
        algorithm: 'khovratovich'
      };
      equihash.solve(hash, equihashOptions, callback);
    }],
    sign: ['proof', (results, callback) => {
      const signed = bedrock.util.clone(options.doc);
      // convert solution to 32 bit big endian buffer
      const ab = new ArrayBuffer(results.proof.solution.length * 4);
      const dv = new DataView(ab);
      results.proof.solution.forEach((v, i) => {
        dv.setUint32(i * 4, v);
      });
      signed.signature = {
        type: 'EquihashProof2017',
        equihashParameterN: results.proof.n,
        equihashParameterK: results.proof.k,
        nonce: results.proof.nonce.toString('base64'),
        proofValue: Buffer.from(ab).toString('base64'),
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
  // FIXME: compact before accessing 'signature' alias
  if(!document.signature) {
    return callback(new TypeError('Missing signature.'));
  }

  const unsignedDocument = bedrock.util.clone(document);
  const signature = unsignedDocument.signature;
  delete unsignedDocument.signature;

  async.auto({
    normalize: callback => bedrock.jsonld.normalize(unsignedDocument, {
      algorithm: 'URDNA2015',
      format: 'application/nquads'
    }, callback),
    validate: callback => {
      if(!signature.proofValue) {
        return callback(new TypeError('Missing proof value.'));
      }
      if(typeof signature.proofValue !== 'string') {
        return callback(new TypeError('Proof value must be a string.'));
      }
      callback();
    },
    verify: ['validate', 'normalize', (results, callback) => {
      const hash =
        crypto.createHash('sha256').update(results.normalize, 'utf8').digest();
      // convert 32 bit big endian buffer solution to array
      const b = Buffer.from(signature.proofValue, 'base64');
      const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
      // convert from 32 bit big endian buffer
      const solution = new Array(b.length / 4);
      for(let i = 0; i < solution.length; ++i) {
        solution[i] = dv.getUint32(i * 4);
      }

      const equihashOptions = {
        n: signature.equihashParameterN,
        k: signature.equihashParameterK,
        nonce: Buffer.from(signature.nonce, 'base64'),
        solution: solution
      };
      equihash.verify(hash, equihashOptions, callback);
    }]
  }, (err, results) => {
    if(err) {
      return callback(err);
    }
    callback(null, results.verify);
  });
};
