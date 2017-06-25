/*
 * Copyright (c) 2016, the IRMA Team
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 *  Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 *  Neither the name of the IRMA project nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


package org.irmacard.credentials.idemix.proofs;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import org.irmacard.credentials.idemix.util.Crypto;
import org.irmacard.credentials.info.PublicKeyIdentifier;

public abstract class Commitments {
	public abstract List<BigInteger> asList();

	public abstract Commitments mergeProofPCommitments(
			ProofPCommitmentMap cmap);

	public BigInteger calculateChallenge(BigInteger context, BigInteger nonce1) {
		return calculateChallenge(context, nonce1, false);
	}

	public BigInteger calculateChallenge(BigInteger context, BigInteger nonce1, boolean isSig) {
		List<BigInteger> lst = new ArrayList<>();
		lst.add(context);
		lst.addAll(asList());
		lst.add(nonce1);

		if (isSig)
			return Crypto.sha256Hash(Crypto.asn1SigEncode(lst));
		else
			return Crypto.sha256Hash(Crypto.asn1Encode(lst));
	}
}
