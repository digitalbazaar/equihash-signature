/*!
 * Copyright (c) 2017 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const equihashSigs = require('equihash-signature');

describe('Equihash Signature API', () => {
  describe('sign', () => {
    it('signs something', done => {
      equihashSigs.sign({
        doc: {id: 'something'},
        n: 4,
        k: 3
      }, (err, result) => {
        // FIXME: is this assertion accurate?
        result.signature.proofValue.should.not.equal('');
        done();
      });
    });
  });
});
