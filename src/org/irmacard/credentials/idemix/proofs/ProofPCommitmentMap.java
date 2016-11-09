package org.irmacard.credentials.idemix.proofs;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;

import org.irmacard.credentials.info.PublicKeyIdentifier;

public class ProofPCommitmentMap extends Commitments {
	private HashMap<PublicKeyIdentifier, ProofPBuilder.ProofPCommitments> c = new LinkedHashMap<>();

	@Override
	public List<BigInteger> asList() {
		List<BigInteger> vals = new ArrayList<>();
		for (ProofPBuilder.ProofPCommitments coms : c.values()) {
			vals.addAll(coms.asList());
		}
		return vals;
	}

	@Override
	public Commitments mergeProofPCommitments(ProofPCommitmentMap map) {
		throw new RuntimeException(
				"ProofPList not compatible with merging ProofPCommits");
	}

	public ProofPBuilder.ProofPCommitments put(PublicKeyIdentifier id,
			ProofPBuilder.ProofPCommitments com) {
		return c.put(id, com);
	}

	public boolean containsKey(PublicKeyIdentifier id) {
		return c.containsKey(id);
	}

	public ProofPBuilder.ProofPCommitments get(PublicKeyIdentifier id) {
		return c.get(id);
	}
}
