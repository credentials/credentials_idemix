package org.irmacard.credentials.idemix.info;

import org.irmacard.credentials.idemix.IdemixPublicKey;
import org.irmacard.credentials.idemix.IdemixSecretKey;
import org.irmacard.credentials.info.BasicFileReader;
import org.irmacard.credentials.info.FileReader;
import org.irmacard.credentials.info.InfoException;

import java.net.URI;

@SuppressWarnings("unused")
public class IdemixKeyStoreDeserializer {
	static private final String PUBLIC_KEY_FILE = "ipk.xml";
	static private final String PRIVATE_KEY_FILE = "private/isk.xml";

	private FileReader fileReader;

	public IdemixKeyStoreDeserializer(URI coreLocation) {
		fileReader = new BasicFileReader(coreLocation);
	}

	public IdemixKeyStoreDeserializer(FileReader reader) {
		this.fileReader = reader;
	}

	public IdemixPublicKey loadPublicKey(String issuer) throws InfoException {
		String path = issuer + "/" + PUBLIC_KEY_FILE;
		return new IdemixPublicKey(fileReader.retrieveFile(path));
	}

	public IdemixSecretKey loadPrivateKey(String issuer) throws InfoException {
		String path = issuer + "/" + PRIVATE_KEY_FILE;
		return new IdemixSecretKey(fileReader.retrieveFile(path));
	}
}
