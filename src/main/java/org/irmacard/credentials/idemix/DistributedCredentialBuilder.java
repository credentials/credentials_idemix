/*
 * Copyright (c) 2015, the IRMA Team
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

package org.irmacard.credentials.idemix;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.security.SecureRandom;
import java.util.Vector;

import org.irmacard.credentials.CredentialsException;
import org.irmacard.credentials.idemix.messages.IssueCommitmentMessage;
import org.irmacard.credentials.idemix.messages.IssueSignatureMessage;
import org.irmacard.credentials.idemix.proofs.ProofListBuilder;
import org.irmacard.credentials.idemix.proofs.ProofPBuilder;
import org.irmacard.credentials.idemix.proofs.ProofPCommitmentMap;
import org.irmacard.credentials.idemix.proofs.ProofPListBuilder;
import org.irmacard.credentials.idemix.proofs.ProofU;
import org.irmacard.credentials.idemix.proofs.ProofUBuilder;
import org.irmacard.credentials.idemix.util.Crypto;

public class DistributedCredentialBuilder extends CredentialBuilder {

	private List<BigInteger> public_sks = new ArrayList<>();

	public DistributedCredentialBuilder(IdemixPublicKey pk, List<BigInteger> attrs, BigInteger context) {
		super(pk, attrs, context);
	}

	public DistributedCredentialBuilder(IdemixPublicKey pk, List<BigInteger> attrs, BigInteger context, BigInteger nonce2) {
		this(pk, attrs, context);
		setNonce2(nonce2);
	}

	public void addPublicSK(BigInteger public_sk) {
		public_sks.add(public_sk);
	}

	public void addPublicSK(ProofPCommitmentMap map) {
		ProofPBuilder.ProofPCommitments coms = map.get(pk.getIdentifier());
		addPublicSK(coms.getP());
	}

	public IdemixDistributedCredential constructCredential(IssueSignatureMessage msg)
			throws CredentialsException {
		if (!msg.getProofS().verify(pk, msg.getSignature(), context, getNonce2())) {
			throw new CredentialsException(
					"The proof of correctness on the signature does not verify");
		}

		// Construct actual signature
		CLSignature psig = msg.getSignature();
		CLSignature signature = new CLSignature(psig.getA(), psig.get_e(), psig
				.get_v().add(getVPrime()));

		// Verify signature
		List<BigInteger> exponents = new Vector<>();
		exponents.add(getSecret());
		exponents.addAll(attributes);

		if (!signature.verifyDistributed(pk, exponents, public_sks)) {
			throw new CredentialsException(
					"Signature on the attributes is not correct");
		}

		return new IdemixDistributedCredential(pk, getSecret(), public_sks, attributes, signature);
	}
}
