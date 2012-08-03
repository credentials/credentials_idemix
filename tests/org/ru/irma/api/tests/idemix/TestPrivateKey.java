package org.ru.irma.api.tests.idemix;

import org.junit.Test;

import credentials.idemix.IdemixPrivateKey;
import static org.junit.Assert.*;

public class TestPrivateKey {
	/**
	 * Verify Idemix-library behavior in case of missing or not yet 
	 * loaded public key. Assuming the library will set the public key
	 * to null in this case.
	 */
	@Test
	public void testMissingPublicKey() {
		IdemixPrivateKey isk = IdemixPrivateKey
				.fromIdemixPrivateKey(TestSetup.ISSUER_SK_LOCATION);
		
		assertNull(isk.getPrivateKey().getPublicKey());
	}
}
