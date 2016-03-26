package org.irmacard.credentials.idemix.info;

import org.irmacard.credentials.idemix.IdemixPublicKey;
import org.irmacard.credentials.idemix.IdemixSecretKey;
import org.irmacard.credentials.info.BasicFileReader;
import org.irmacard.credentials.info.FileReader;
import org.irmacard.credentials.info.InfoException;
import org.irmacard.credentials.info.IssuerIdentifier;

import java.net.URI;

@SuppressWarnings("unused")
public class IdemixKeyStoreDeserializer {
	private FileReader fileReader;

	public IdemixKeyStoreDeserializer(URI coreLocation) {
		fileReader = new BasicFileReader(coreLocation);
	}

	public IdemixKeyStoreDeserializer(FileReader reader) {
		this.fileReader = reader;
	}

	public IdemixPublicKey loadPublicKey(IssuerIdentifier issuer) throws InfoException {
		String path = issuer.getPath(false) + "/" + IdemixKeyStore.PUBLIC_KEY_FILE;
		return new IdemixPublicKey(fileReader.retrieveFile(path));
	}

	public IdemixSecretKey loadPrivateKey(IssuerIdentifier issuer) throws InfoException {
		String path = issuer.getPath(false) + "/" + IdemixKeyStore.PRIVATE_KEY_FILE;
		return new IdemixSecretKey(fileReader.retrieveFile(path));
	}
}
