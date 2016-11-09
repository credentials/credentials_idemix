package org.irmacard.credentials.idemix.proofs;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.irmacard.credentials.idemix.IdemixPublicKey;
import org.irmacard.credentials.idemix.info.IdemixKeyStore;
import org.irmacard.credentials.idemix.proofs.ProofPBuilder.ProofPCommitments;
import org.irmacard.credentials.info.InfoException;
import org.irmacard.credentials.info.KeyException;
import org.irmacard.credentials.info.PublicKeyIdentifier;

public class ProofPListBuilder {
	List<IdemixPublicKey> pks;
	List<ProofPBuilder> builders;

	public ProofPListBuilder(List<PublicKeyIdentifier> pkids, BigInteger secret) throws InfoException, KeyException {
		IdemixKeyStore store = IdemixKeyStore.getInstance();

		pks = new ArrayList<>();
		builders = new ArrayList<>();

		for(PublicKeyIdentifier pkid : pkids) {
			IdemixPublicKey pk = store.getPublicKey(pkid);
			pks.add(pk);
			builders.add(new ProofPBuilder(secret, pk));
		}
	}

	public ProofPListBuilder generateRandomizers() {
		SecureRandom rnd = new SecureRandom();

		// FIXME: size of randomness for key could be different for different parameters!
		Map<String, BigInteger> fixed = new HashMap<>();
		fixed.put(ProofBuilder.CLOUD_SECRET_KEY,
				new BigInteger(pks.get(0).getSystemParameters().get_l_m_commit(), rnd));

		for(ProofPBuilder builder : builders) {
			builder.generateRandomizers(fixed);
		}
		return this;
	}

	public ProofPCommitmentMap calculateCommitments() {
		ProofPCommitmentMap coms = new ProofPCommitmentMap();
		for(int i = 0; i < pks.size(); i++) {
			ProofPBuilder builder = builders.get(i);
			PublicKeyIdentifier id = pks.get(i).getIdentifier();
			coms.put(id, builder.calculateCommitments());
		}
		return coms;
	}

	public ProofP build(BigInteger challenge) {
		// Nice fact, since the randomizers are all the same
		// per construction, so will all the proofs be the same
		// hence, we only need to return one proof.
		
		// FIXME: this response is only valid for the first pk
		// not for any of the other keys, not so nice
		ProofPBuilder builder = builders.get(0);
		return builder.createProof(challenge);
	}
}