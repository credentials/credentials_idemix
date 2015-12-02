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

import org.irmacard.credentials.CredentialsException;
import org.irmacard.credentials.idemix.messages.IssueCommitmentMessage;
import org.irmacard.credentials.idemix.messages.IssueSignatureMessage;
import org.irmacard.credentials.idemix.proofs.ProofCollection;
import org.irmacard.credentials.idemix.proofs.ProofS;
import org.irmacard.credentials.idemix.util.Crypto;

public class IdemixIssuer {
	private IdemixSecretKey sk;
	private IdemixPublicKey pk;

	private BigInteger context;

	public IdemixIssuer(IdemixPublicKey pk, IdemixSecretKey sk,
			BigInteger context) {

		this.pk = pk;
		this.sk = sk;

		this.context = context;
	}

	/**
	 * Returns a signature and corresponding proof on the given attributes. As
	 * per the protocol, it will include the commitment U into the signature.
	 * Note that the signature itself does not verify (see
	 * {@link #signCommitmentAndAttributes(BigInteger, List)}).
	 * <p>
	 * If the IssueCommitmentMessage contains multiple proofs of knowledge in a
	 * {@link ProofCollection} then this method verifies the validity of all these
	 * proofs, but it does not check if the disclosure proofs with the correct
	 * attributes are included in the collection (as we have no way of knowing
	 * which attributes are expected here).
	 *
	 * @param msg
	 *            Message from the user, containing U; one or more proofs of knowledge; and
	 *            the nonce over which we should create our own proof of knowledge
	 * @param attrs
	 *            Attributes to include in the signature
	 * @param nonce1
	 *            Nonce from the recipient
	 * @return Signature on attributes+commitments and the proof of correctness
	 * @throws CredentialsException when the commitment proof(s) is/are not correct
	 */
	protected IssueSignatureMessage issueSignature(IssueCommitmentMessage msg,
			List<BigInteger> attrs, BigInteger nonce1) throws CredentialsException {
		if (msg.getCombinedProofs() == null && msg.getCommitmentProof() == null) {
			throw new CredentialsException("No ProofU found in message");
		}

		BigInteger U;

		if (msg.getCombinedProofs() != null) {
			ProofCollection proofs = msg.getCombinedProofs();
			U = proofs.getProofU().getU();
			if (!proofs.verify(context, nonce1, true)) {
				throw new CredentialsException("The combined proofs are not correct");
			}
		}
		else {
			U = msg.getCommitmentProof().getU();
			if (!msg.getCommitmentProof().verify(pk, context, nonce1)) {
				throw new CredentialsException("The commitment proof is not correct");
			}
		}

		CLSignature signature = signCommitmentAndAttributes(U, attrs);
		ProofS proof = proveSignature(signature, msg.getNonce2());

		return new IssueSignatureMessage(signature, proof);
	}

	/**
	 * Signature on the commitment and the attributes. The signature by itself
	 * does not verify because the commitment contains a blinding factor that
	 * needs to be taken into account when verifying the signature.
	 *
	 * @param U
	 *            Commitment to secret
	 * @param attrs
	 *            List of attributes
	 * @return A (partial) CL signature on the commitment and attributes.
	 */
	protected CLSignature signCommitmentAndAttributes(BigInteger U,
			List<BigInteger> attrs) {

		return CLSignature.signMessageBlockAndCommitment(sk, pk, U, attrs);
	}

	/**
	 * Proof of the knowledge of $e^{-1}$ in the signature.
	 *
	 * TODO: We work with the group_modulus = p'q' a lot, this has side channel
	 * implications.
	 *
	 * @param signature
	 *            Camenisch-Lysyanskaya signature
	 * @param n_2
	 *            Nonce
	 * @return A proof of knowledge of e^{-1}
	 */
	public ProofS proveSignature(CLSignature signature, BigInteger n_2) {
		BigInteger n = pk.getModulus();
		BigInteger Q = signature.getA().modPow(signature.get_e(), n);
		BigInteger group_modulus = sk.get_p_prime_q_prime();
		BigInteger e_inverse = signature.get_e().modInverse(group_modulus);

		BigInteger e_commit = Crypto
				.randomElementMultiplicativeGroup(group_modulus);
		BigInteger A_commit = Q.modPow(e_commit, n);

		BigInteger c = Crypto.sha256Hash(Crypto.asn1Encode(context, Q,
				signature.getA(), n_2, A_commit));

		BigInteger e_response = e_commit.subtract(c.multiply(e_inverse))
				.mod(group_modulus);

		return new ProofS(c, e_response);
	}

	public BigInteger getContext() {
		return context;
	}
}
