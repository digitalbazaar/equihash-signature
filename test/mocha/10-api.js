/*!
 * Copyright (c) 2017-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const equihashSigs = require('equihash-signature');
const jsigs = require('jsonld-signatures');
equihashSigs.install(jsigs);

describe('Equihash Signature API', () => {
  describe('sign', () => {
    it('signs something', done => {
      jsigs.sign({
        '@context': 'https://w3id.org/security/v2',
        id: 'foo:something'
      }, {
        algorithm: 'EquihashProof2018',
        parameters: {
          n: 64,
          k: 3
        }
      }, (err, result) => {
        // FIXME: is this assertion accurate?
        result.proof.proofValue.should.not.equal('');
        done();
      });
    });
  });
});
