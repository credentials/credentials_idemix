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
import java.security.SecureRandom;
import java.util.Vector;

import org.irmacard.credentials.CredentialsException;
import org.irmacard.credentials.idemix.messages.IssueCommitmentMessage;
import org.irmacard.credentials.idemix.messages.IssueSignatureMessage;
import org.irmacard.credentials.idemix.proofs.ProofListBuilder;
import org.irmacard.credentials.idemix.proofs.ProofU;
import org.irmacard.credentials.idemix.proofs.ProofUBuilder;
import org.irmacard.credentials.idemix.util.Crypto;

public class CredentialBuilder {
	// State
	private BigInteger s;
	private BigInteger v_prime;
	private BigInteger n_2;
	private BigInteger U;

	// Immutable Input
	protected final IdemixPublicKey pk;
	protected final List<BigInteger> attributes;
	protected final BigInteger context;

	// Derived immutable state
	protected final IdemixSystemParameters params;
	protected final BigInteger n;

	public CredentialBuilder(IdemixPublicKey pk, List<BigInteger> attrs, BigInteger context) {
		this.pk = pk;
		this.attributes = attrs;
		this.context = context;

		this.params = pk.getSystemParameters();
		this.n = pk.getModulus();
		this.n_2 = createReceiverNonce();
	}

	public CredentialBuilder(IdemixPublicKey pk, List<BigInteger> attrs, BigInteger context, BigInteger nonce2) {
		this(pk, attrs, context);
		this.n_2 = nonce2;
	}

	public IdemixPublicKey getPublicKey() {
		return pk;
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
		ProofU proofU = proveCommitment(nonce1);

		return new IssueCommitmentMessage(proofU, n_2);
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
		List<BigInteger> exponents = new Vector<>();
		exponents.add(s);
		exponents.addAll(attributes);

		if (!signature.verify(pk, exponents)) {
			throw new CredentialsException(
					"Signature on the attributes is not correct");
		}

		return new IdemixCredential(pk, s, attributes, signature);
	}

	public void setSecret(BigInteger secret) {
		// State that needs to be stored
		this.s = secret;
	}

	public BigInteger getSecret() {
		return s;
	}

	public BigInteger getVPrime() {
		return v_prime;
	}

	public BigInteger getNonce2() {
		return n_2;
	}

	public void setNonce2(BigInteger nonce2) {
		this.n_2 = nonce2;
	}

	public BigInteger commitmentToSecret() {
		if (U == null) {
			// FIXME: Not according to protocol, only positives possible this way
			//v_prime = Crypto.randomSignedInteger(params.l_v_prime);
			v_prime = Crypto.randomUnsignedInteger(params.get_l_v_prime());

			// U = S^{v_prime} * R_0^{s}
			BigInteger Sv = pk.getGeneratorS().modPow(v_prime, n);
			BigInteger R0s = pk.getGeneratorR(0).modPow(s, n);
			U = Sv.multiply(R0s).mod(n);
		}

		return U;
	}

	protected ProofU proveCommitment(BigInteger n_1) {
		ProofUBuilder pb = new ProofUBuilder(this);
		return (ProofU) pb.createProof(context, n_1);
	}

	public static BigInteger createReceiverNonce(IdemixSystemParameters params) {
		return new BigInteger(params.get_l_statzk(), new SecureRandom());
	}

	public static BigInteger createReceiverNonce(IdemixPublicKey pk) {
		return createReceiverNonce(pk.getSystemParameters());
	}

	public BigInteger createReceiverNonce() {
		return createReceiverNonce(pk);
	}

	/*
	public Commitment commit(BigInteger nonce1, BigInteger skCommit) {
		if (n_2 == null)
			n_2 = createReceiverNonce();

		return new Commitment(nonce1, skCommit);
	}*/
}
