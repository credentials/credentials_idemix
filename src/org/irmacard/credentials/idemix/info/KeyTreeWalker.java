package org.irmacard.credentials.idemix.info;

import org.irmacard.credentials.info.DescriptionStore;
import org.irmacard.credentials.info.InfoException;
import org.irmacard.credentials.info.IssuerDescription;

public class KeyTreeWalker {
	private IdemixKeyStoreDeserializer deserializer;

	public KeyTreeWalker(IdemixKeyStoreDeserializer deserializer) {
		this.deserializer = deserializer;
	}

	public void deserializeIdemixKeyStore(IdemixKeyStore store) throws InfoException {
		DescriptionStore ds = DescriptionStore.getInstance();

		for (IssuerDescription id : ds.getIssuerDescriptions()) {
			try {
				store.setPublicKey(id.getIdentifier(), deserializer.loadPublicKey(id.getIdentifier()));
			} catch (InfoException e) { /* ignore absence of public key */ }

			try {
				store.setSecretKey(id.getIdentifier(), deserializer.loadPrivateKey(id.getIdentifier()));
			} catch (InfoException e) { /* ignore absence of private key */ }
		}
	}
}
