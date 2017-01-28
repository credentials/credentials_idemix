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

package org.irmacard.credentials.idemix.proofs;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import de.henku.jpaillier.PublicKey;
import org.irmacard.credentials.idemix.IdemixPublicKey;
import org.irmacard.credentials.idemix.IdemixSystemParameters;
import org.irmacard.credentials.info.PublicKeyIdentifier;

public class ProofPBuilder extends ProofBuilder {
	private BigInteger s;
	private IdemixPublicKey pk;
	private BigInteger P;

	ProofPRandomizers rand;

	class ProofPRandomizers implements Randomizers {
		private BigInteger s_randomizer;
	}

	public class ProofPCommitments extends Commitments {
		private BigInteger P;
		private BigInteger Pcommit;

		@Override
		public List<BigInteger> asList() {
			return Arrays.asList(P, Pcommit);
		}

		@Override
		public Commitments mergeProofPCommitments(
				ProofPCommitmentMap map) {
			// For now we do not need this, we might never need it
			throw new RuntimeException("Not yet implemented!");
		}

		public BigInteger getPcommit() {
			return Pcommit;
		}

		public BigInteger getP() {
			return P;
		}
	}

	public ProofPBuilder(BigInteger s, IdemixPublicKey pk) {
		this.s = s;
		this.pk = pk;

		this.P = pk.getGeneratorR(0).modPow(s, pk.getModulus());
	}

	@Override
	public ProofBuilder generateRandomizers(Map<String, BigInteger> fixed) {
		SecureRandom rnd = new SecureRandom();
		rand = new ProofPRandomizers();

		IdemixSystemParameters params = pk.getSystemParameters();
		rand.s_randomizer = new BigInteger(params.get_l_m_commit(), rnd);
		if(fixed != null) {
			if(fixed.containsKey(ProofBuilder.CLOUD_SECRET_KEY)) {
				rand.s_randomizer = fixed.get(ProofBuilder.CLOUD_SECRET_KEY);
			}
		}

		return null;
	}

	@Override
	public ProofPCommitments calculateCommitments() {
		ProofPCommitments coms = new ProofPCommitments();

		coms.P = P;
		coms.Pcommit = pk.getGeneratorR(0).modPow(rand.s_randomizer, pk.getModulus());

		return coms;
	}

	@Override
	public ProofP createProof(BigInteger challenge) {
		return createProof(challenge, (PublicKey) null);
	}

	public ProofP createProof(BigInteger challenge, PublicKey publicKey) {
		BigInteger s_response;

		// Even if we have a public key, the challenge might be unencrypted
		if (publicKey == null || ! isPaillierCiphertext(challenge)) {
			s_response = rand.s_randomizer.add(challenge.multiply(s));
		} else {
			s_response = publicKey.encrypt(rand.s_randomizer).multiply(
					challenge.modPow(s, publicKey.getnSquared())).mod(publicKey.getnSquared());
		}

		return new ProofP(P, challenge, s_response);
	}

	/**
	 * Dirty way of deciding if this is a Paillier ciphertext, or a plaintext integer:
	 * even with a Paillier public key of 1024 bits, which is so unsafe that we would
	 * never use it, a Paillier ciphertext would be larger than 2048 bits, while an IRMA
	 * challenge will never be that long.
	 */
	private static boolean isPaillierCiphertext(BigInteger challenge) {
		return challenge.bitLength() > 2000;
	}

	@Override
	public IdemixPublicKey getPublicKey() {
		return pk;
	}
}
