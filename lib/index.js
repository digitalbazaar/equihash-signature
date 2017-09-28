/*!
 * Copyright (c) 2017 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const _ = require('lodash');
const async = require('async');
const crypto = require('crypto');
const equihash = require('equihash');

const _nodejs = (
  typeof process !== 'undefined' && process.versions && process.versions.node);

const api = {};
const libs = {};
// NOTE: only exported for tests
module.exports = api;

api.use = (name, injectable) => {
  // setter mode
  if(injectable) {
    libs[name] = injectable;
    return;
  }

  // getter mode:

  // api not set yet, load default
  if(!libs[name]) {
    const requireAliases = {};
    const requireName = requireAliases[name] || name;
    const globalName = (name === 'jsonld' ? 'jsonldjs' : name);
    libs[name] = global[globalName] || (_nodejs && require(requireName));
    if(name === 'jsonld') {
      if(_nodejs) {
        // locally configure jsonld
        libs[name] = libs[name]();
        libs[name].useDocumentLoader('node', {secure: true, strictSSL: true});
      }
    }
  }
  return libs[name];
};

api.sign = (options, callback) => {
  // FIXME: deal with docs that already have signatures
  // FIXME: compact before accessing 'signature' alias
  if(options.doc.signature) {
    return callback(
      new TypeError('Signing a document with a signature not yet supported.'));
  }

  const jsonld = api.use('jsonld');
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
      const signed = _.cloneDeep(options.doc);
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

  const unsignedDocument = _.cloneDeep(document);
  const signature = unsignedDocument.signature;
  delete unsignedDocument.signature;

  const jsonld = api.use('jsonld');
  async.auto({
    normalize: callback => jsonld.normalize(unsignedDocument, {
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
