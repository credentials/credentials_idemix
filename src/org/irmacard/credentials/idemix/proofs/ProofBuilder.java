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
import java.util.Map;

import org.irmacard.credentials.idemix.IdemixPublicKey;
import org.irmacard.credentials.idemix.util.Crypto;

/**
 * Proof builders create the proofs for our IRMA protocols. They do not contain much state,
 * they only keep track of the common proof information, the private prover information
 * and the randomizers that are required for the proof. A user must generate randomizers
 * before attempting to build a proof.
 *
 * @author wouter
 *
 */
public abstract class ProofBuilder {
	public static final String USER_SECRET_KEY = "user-secret-key";

	public abstract ProofBuilder generateRandomizers(Map<String, BigInteger> fixed);
	public abstract Commitments calculateCommitments();
	public abstract Proof createProof(BigInteger challenge);
	public abstract IdemixPublicKey getPublicKey();

	public ProofBuilder generateRandomizers() {
		HashMap<String, BigInteger> h = new HashMap<>();
		generateRandomizers(h);
		return this;
	}

	public Proof createProof(BigInteger context, BigInteger nonce1) {
		generateRandomizers();
		Commitments coms = calculateCommitments();
		BigInteger challenge = coms.calculateChallenge(context, nonce1);
		return createProof(challenge);
	}
}
