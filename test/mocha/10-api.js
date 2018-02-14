/*!
 * Copyright (c) 2017-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const equihashSigs = require('equihash-signature');
const jsigs = require('jsonld-signatures');
equihashSigs.install(jsigs);

const testDoc = {
  "@context": "https://w3id.org/security/v2",
  "id": "foo:something",
  "proof": {
    "type": "EquihashProof2018",
    "created": "2018-02-14T23:27:45Z",
    "equihashParameterK": 3,
    "equihashParameterN": 64,
    "nonce": "AQAAAA==",
    "proofValue": "AABBiAAAnTAAALM8AAGc0AAArs4AAaiYAAE2HQABvyw="
  }
};

describe('Equihash Signature API', () => {
  it('sign', done => {
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

  it('verify', done => {
    jsigs.verify(testDoc, (err, result) => {
      result.verified.should.equal(true);
      done();
    });
  });
});
