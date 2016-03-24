package org.irmacard.credentials.idemix.info;

import org.irmacard.credentials.info.IssuerDescription;

public interface IdemixKeyStoreSerializer {
	void saveIdemixKey(IssuerDescription issuer, String key,
	                   String groupParameters, String SystemParameters);
}
