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
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.irmacard.credentials.idemix.CLSignature;
import org.irmacard.credentials.idemix.CredentialBuilder;
import org.irmacard.credentials.idemix.IdemixPublicKey;
import org.irmacard.credentials.idemix.IdemixSystemParameters;
import org.irmacard.credentials.idemix.proofs.ProofPBuilder.ProofPCommitments;
import org.irmacard.credentials.idemix.util.Crypto;

public class ProofUBuilder extends ProofBuilder {
	private CredentialBuilder cb;

	private ProofURandomizers rand;

	class ProofURandomizers implements Randomizers {
		private BigInteger v_prime_commit;
		private BigInteger s_commit;
	}

	class ProofUCommitments extends Commitments {
		private BigInteger U;
		private BigInteger U_commit;
		private IdemixPublicKey pk;

		public ProofUCommitments(IdemixPublicKey pk) {
			this.pk = pk;
		}

		public List<BigInteger> asList() {
			List<BigInteger> lst = Arrays.asList(U, U_commit);
			return lst;
		}

		@Override
		public Commitments mergeProofPCommitments(ProofPBuilder.ProofPCommitments coms) {
			U_commit = U_commit.multiply(coms.getPcommit()).mod(pk.getModulus());
			return this;
		}
	}

	public ProofUBuilder(CredentialBuilder cb) {
		rand = new ProofURandomizers();

		this.cb = cb;
	}

	@Override
	public ProofBuilder generateRandomizers(Map<String, BigInteger> fixed) {
		IdemixSystemParameters params = cb.getPublicKey().getSystemParameters();
		rand.v_prime_commit = Crypto.randomUnsignedInteger(params.get_l_v_prime_commit());

		if (fixed.containsKey(USER_SECRET_KEY)) {
			rand.s_commit = fixed.get(USER_SECRET_KEY);
		} else {
			rand.s_commit = Crypto.randomUnsignedInteger(params.get_l_s_commit());
		}

		return this;
	}

	@Override
	public Commitments calculateCommitments() {
		ProofUCommitments coms = new ProofUCommitments(cb.getPublicKey());
		IdemixPublicKey pk = cb.getPublicKey();
		BigInteger n = pk.getModulus();

		coms.U = cb.commitmentToSecret();

		// U_commit = S^{v_prime_commit} * R_0^{s_commit}
		BigInteger Sv = pk.getGeneratorS().modPow(rand.v_prime_commit, n);
		BigInteger R0s = pk.getGeneratorR(0).modPow(rand.s_commit, n);
		coms.U_commit = Sv.multiply(R0s).mod(n);

		return coms;
	}

	@Override
	public Proof createProof(BigInteger challenge) {
		BigInteger s_response = rand.s_commit.add(challenge.multiply(cb.getSecret()));
		BigInteger v_prime_response = rand.v_prime_commit.add(challenge.multiply(cb.getVPrime()));

		return new ProofU(cb.commitmentToSecret(), challenge, v_prime_response, s_response);
	}

	@Override
	public IdemixPublicKey getPublicKey() {
		return cb.getPublicKey();
	}
}
