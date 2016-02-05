package org.irmacard.credentials.idemix.info;

import org.irmacard.credentials.info.InfoException;

public interface IdemixKeyStoreDeserializerI {
	IdemixKeyStore deserializeIdemixKeyStore() throws InfoException;
}
