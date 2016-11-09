package org.irmacard.credentials.idemix;

import static org.junit.Assert.*;

import java.io.File;
import java.math.BigInteger;
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.Random;

import org.irmacard.credentials.Attributes;
import org.irmacard.credentials.idemix.info.IdemixKeyStore;
import org.irmacard.credentials.idemix.info.IdemixKeyStoreDeserializer;
import org.irmacard.credentials.idemix.proofs.ProofD;
import org.irmacard.credentials.idemix.proofs.ProofList;
import org.irmacard.credentials.idemix.proofs.ProofListBuilder;
import org.irmacard.credentials.info.CredentialIdentifier;
import org.irmacard.credentials.info.DescriptionStore;
import org.irmacard.credentials.info.DescriptionStoreDeserializer;
import org.irmacard.credentials.info.InfoException;
import org.irmacard.credentials.info.IssuerIdentifier;
import org.irmacard.credentials.info.KeyException;
import org.irmacard.credentials.info.PublicKeyIdentifier;
import org.junit.Test;

public class IRMAStoreTest {
	@Test
	public void AttributesTest() throws InfoException, KeyException {
		URI core = new File(System.getProperty("user.dir")).toURI().resolve("irma_configuration/");
		DescriptionStore.initialize(new DescriptionStoreDeserializer(core));
		IdemixKeyStore.initialize(new IdemixKeyStoreDeserializer(core));
		
		IssuerIdentifier issuer = new IssuerIdentifier("irma-demo.MijnOverheid");
		IdemixPublicKey pk = IdemixKeyStore.getInstance().getPublicKey(
				new PublicKeyIdentifier(issuer, 0));
		IdemixSecretKey sk = IdemixKeyStore.getInstance().getSecretKey(issuer, 0);

		CredentialIdentifier ageLower = new CredentialIdentifier("irma-demo.MijnOverheid.ageLower");
		Date time = new Date(Calendar.getInstance().getTimeInMillis()
				/ Attributes.EXPIRY_FACTOR * Attributes.EXPIRY_FACTOR);
		short keyCounter = 0;
		short duration = 10;

		Attributes attributes = new Attributes();
		attributes.add("over12", "yes".getBytes());
		attributes.add("over16", "yes".getBytes());
		attributes.add("over18", "no".getBytes());
		attributes.add("over21", "no".getBytes());

		attributes.setCredentialIdentifier(ageLower);
		attributes.setKeyCounter(keyCounter);
		attributes.setValidityDuration(duration);
		attributes.setSigningDate(time);

		ArrayList<BigInteger> bigints = attributes.toBigIntegers();
		bigints.add(0, BigInteger.TEN); // secret key
		CLSignature signature1 = CLSignature.signMessageBlock(sk, pk, bigints);
		IdemixCredential cred1 = new IdemixCredential(pk, bigints, signature1);

		Random rnd = new Random();
		IdemixSystemParameters params = pk.getSystemParameters();
		BigInteger context = new BigInteger(params.get_l_h(), rnd);
		BigInteger nonce1 = new BigInteger(params.get_l_statzk(), rnd);

		ProofList collection = new ProofListBuilder(context, nonce1)
				.addProofD(cred1, Arrays.asList(1, 2))
				.build();

		Attributes disclosed = new Attributes(((ProofD)collection.get(0)).get_a_disclosed());
		assertTrue("Attributes should be valid", disclosed.isValid());
		assertTrue("Credential identifiers should match", disclosed.getCredentialIdentifier().equals(ageLower));
		assertTrue("Key counters should match", disclosed.getKeyCounter() == keyCounter);
		assertTrue("Validity duration should match", disclosed.getValidityDuration() == duration);
		assertTrue("Issuing dates should match", disclosed.getSigningDate().equals(time));
	}
}
