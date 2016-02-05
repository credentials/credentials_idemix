package org.irmacard.credentials.idemix.info;

import org.irmacard.credentials.idemix.IdemixPublicKey;
import org.irmacard.credentials.idemix.IdemixSecretKey;
import org.irmacard.credentials.info.DescriptionStore;
import org.irmacard.credentials.info.InfoException;
import org.irmacard.credentials.info.IssuerDescription;
import org.irmacard.credentials.info.TreeWalkerI;

import java.net.URI;
import java.net.URISyntaxException;

public class IdemixKeyStoreDeserializer implements IdemixKeyStoreDeserializerI {
	static private URI CORE_LOCATION;
	static private TreeWalkerI treeWalker;

	static private final String PUBLIC_KEY_FILE = "ipk.xml";
	static private final String PRIVATE_KEY_FILE = "private/isk.xml";

	public IdemixKeyStoreDeserializer(URI location, TreeWalkerI treeWalker) {
		IdemixKeyStoreDeserializer.CORE_LOCATION = location;
		IdemixKeyStoreDeserializer.treeWalker = treeWalker;
	}

	@Override
	public IdemixKeyStore deserializeIdemixKeyStore() throws InfoException {
		IdemixKeyStore store = new IdemixKeyStore();
		DescriptionStore ds = DescriptionStore.getInstance();

		for (IssuerDescription id : ds.getIssuerDescriptions()) {
			URI pkPath, skPath;
			try {
				pkPath = new URI(id.getID() + "/").resolve(PUBLIC_KEY_FILE);
				skPath = new URI(id.getID() + "/").resolve(PRIVATE_KEY_FILE);
			} catch (URISyntaxException e) {
				e.printStackTrace();
				throw new RuntimeException();
			}

			try {
				/*
				 * TODO: this is a bit of cludge, better refactor
				 * IssuerDescription into EntityDescription which is subclassed
				 * by IssuerDescription and Verifier Description, or something
				 * like that.
				 */
				IdemixPublicKey ipk = new IdemixPublicKey(treeWalker.retrieveFile(pkPath));
				store.setPublicKey(id.getID(), ipk);
			} catch (InfoException e) {
				// Ignoring Entity when no key is found
			}

			try {
				IdemixSecretKey isk = new IdemixSecretKey(treeWalker.retrieveFile(skPath));
				store.setSecretKey(id.getID(), isk);
			} catch (InfoException e) {
				// Ignore absence of secret key
			}
		}

		return store;
	}
}
