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
				store.setPublicKey(id.getID(), deserializer.loadPublicKey(id.getID()));
			} catch (InfoException e) { /* ignore absence of public key */ }

			try {
				store.setSecretKey(id.getID(), deserializer.loadPrivateKey(id.getID()));
			} catch (InfoException e) { /* ignore absence of private key */ }
		}
	}
}
