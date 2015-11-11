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
import java.util.List;
import java.util.Random;
import java.util.Vector;

import org.irmacard.credentials.CredentialsException;
import org.irmacard.credentials.idemix.messages.IssueCommitmentMessage;
import org.irmacard.credentials.idemix.messages.IssueSignatureMessage;
import org.irmacard.credentials.idemix.proofs.ProofU;
import org.irmacard.credentials.idemix.util.Crypto;

public class CredentialBuilder {
	// State
	private BigInteger s;
	private BigInteger v_prime;
	private BigInteger n_2;

	// Immutable Input
	private final IdemixPublicKey pk;
	private final List<BigInteger> attributes;
	private final BigInteger context;

	// Derived immutable state
	private final IdemixSystemParameters params;
	private final BigInteger n;

	public CredentialBuilder(IdemixPublicKey pk, List<BigInteger> attrs, BigInteger context) {
		this.pk = pk;
		this.attributes = attrs;
		this.context = context;

		this.params = pk.getSystemParameters();
		this.n = pk.getModulus();
	}

	/**
	 * Response to the initial challenge nonce nonce1 sent by the issuer. The
	 * response consists of a commitment to the secret (@see setSecret) and a
	 * proof of correctness of this commitment. This is the second message in
	 * the issuance protocol.
	 *
	 * @param secret
	 *            The secret that we commit to
	 * @param nonce1
	 *            The challenge nonce sent by the issuer
	 * @return The commitment and proof of correctness of this commitment.
	 */
	public IssueCommitmentMessage commitToSecretAndProve(BigInteger secret,
			BigInteger nonce1) {

		setSecret(secret);

		BigInteger U = commitmentToSecret();
		ProofU proofU = proveCommitment(U, nonce1);
		n_2 = createReceiverNonce();

		return new IssueCommitmentMessage(U, proofU, n_2);
	}

	public IdemixCredential constructCredential(IssueSignatureMessage msg)
			throws CredentialsException {
		if (!msg.getProofS().verify(pk, msg.getSignature(), context, n_2)) {
			throw new CredentialsException(
					"The proof of correctness on the signature does not verify");
		}

		// Construct actual signature
		CLSignature psig = msg.getSignature();
		CLSignature signature = new CLSignature(psig.getA(), psig.get_e(), psig
				.get_v().add(v_prime));

		// Verify signature
		List<BigInteger> exponents = new Vector<BigInteger>();
		exponents.add(s);
		exponents.addAll(attributes);

		if (!signature.verify(pk, exponents)) {
			throw new CredentialsException(
					"Signature on the attributes is not correct");
		}

		return new IdemixCredential(pk, s, attributes, signature);
	}

	protected void setSecret(BigInteger secret) {
		// State that needs to be stored
		this.s = secret;
	}

	protected BigInteger commitmentToSecret() {
		// State that needs to be stored

		// FIXME: Not according to protocol, only positives possible this way
		//v_prime = Crypto.randomSignedInteger(params.l_v_prime);
		v_prime = Crypto.randomUnsignedInteger(params.l_v_prime);

		// U = S^{v_prime} * R_0^{s}
		BigInteger Sv = pk.getGeneratorS().modPow(v_prime, n);
		BigInteger R0s = pk.getGeneratorR(0).modPow(s, n);
		BigInteger U = Sv.multiply(R0s).mod(n);

		return U;
	}

	protected ProofU proveCommitment(BigInteger U, BigInteger n_1) {
		// FIXME Not according to protocol, should be signed values
		//BigInteger s_commit = Crypto.randomSignedInteger(params.l_s_commit);
		//BigInteger v_prime_commit = Crypto.randomSignedInteger(params.l_v_prime_commit);
		BigInteger s_commit = Crypto.randomUnsignedInteger(params.l_s_commit);
		BigInteger v_prime_commit = Crypto.randomUnsignedInteger(params.l_v_prime_commit);

		// U_commit = S^{v_prime_commit} * R_0^{s_commit}
		BigInteger Sv = pk.getGeneratorS().modPow(v_prime_commit, n);
		BigInteger R0s = pk.getGeneratorR(0).modPow(s_commit, n);
		BigInteger U_commit = Sv.multiply(R0s).mod(n);

		BigInteger c = Crypto.sha256Hash(Crypto.asn1Encode(context, U, U_commit, n_1));

		BigInteger s_response = s_commit.add(c.multiply(s));
		BigInteger v_prime_response = v_prime_commit.add(c.multiply(v_prime));

		return new ProofU(c, v_prime_response, s_response);
	}

	private BigInteger createReceiverNonce() {
		Random rnd = new Random();
		return new BigInteger(params.l_statzk, rnd);
	}
}
