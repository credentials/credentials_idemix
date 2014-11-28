/**
 * IdemixIssuer.java
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (C) Wouter Lueks, Radboud University Nijmegen, November 2014.
 */

package org.irmacard.credentials.idemix;

import java.math.BigInteger;
import java.util.List;

import org.irmacard.credentials.CredentialsException;
import org.irmacard.credentials.idemix.messages.IssueCommitmentMessage;
import org.irmacard.credentials.idemix.messages.IssueSignatureMessage;
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
	 * Note that the signature itself does not verify (@see
	 * signCommitmentAndAttributes).
	 *
	 * @param U
	 *            Commitment to the user's secret
	 * @param attrs
	 *            Attributes to include in the signature
	 * @param nonce1
	 *            Nonce from the recipient
	 * @return Signature on attributes+commitments and the proof of correctness
	 * @throws CredentialsException when the commitment proof is not correct
	 */
	protected IssueSignatureMessage issueSignature(IssueCommitmentMessage msg,
			List<BigInteger> attrs, BigInteger nonce1) throws CredentialsException {

		BigInteger U = msg.getCommitment();
		if(!msg.getCommitmentProof().verify(pk, U, context, nonce1)) {
			throw new CredentialsException("The commitment proof is not correct");
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
