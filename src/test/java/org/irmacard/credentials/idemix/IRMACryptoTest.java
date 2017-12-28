/**
 * IRMACryptoTest.java
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (C) Wouter Lueks, Radboud University Nijmegen, November 2014.
 */


package org.irmacard.credentials.idemix;

import org.irmacard.credentials.CredentialsException;
import org.irmacard.credentials.idemix.info.IdemixKeyStore;
import org.irmacard.credentials.idemix.info.IdemixKeyStoreDeserializer;
import org.irmacard.credentials.idemix.messages.IssueCommitmentMessage;
import org.irmacard.credentials.idemix.messages.IssueSignatureMessage;
import org.irmacard.credentials.idemix.proofs.*;
import org.irmacard.credentials.idemix.util.Crypto;
import org.irmacard.credentials.info.*;
import org.junit.Test;

import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.SecureRandom;
import java.util.*;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class IRMACryptoTest {
	List<BigInteger> attributes = Arrays.asList(
			new BigInteger(1, "one".getBytes()),
			new BigInteger(1, "two".getBytes()),
			new BigInteger(1, "three".getBytes()),
			new BigInteger(1, "four".getBytes()));


	static IdemixSecretKey sk = null;
	static IdemixPublicKey pk = null;

	static {
		try {
			URI core = IRMACryptoTest.class.getClassLoader().getResource("irma_configuration/").toURI();
			DescriptionStore.initialize(new DescriptionStoreDeserializer(core));
			IdemixKeyStore.initialize(new IdemixKeyStoreDeserializer(core));

			IssuerIdentifier mo = new IssuerIdentifier("irma-demo.MijnOverheid");
			sk = IdemixKeyStore.getInstance().getSecretKey(mo, 1);
			pk = IdemixKeyStore.getInstance().getPublicKey(mo, 1);
		} catch (InfoException|KeyException|URISyntaxException e) {
			e.printStackTrace();
		}
	}

	@Test
	public void testCLSignature() {
		List<BigInteger> ms = new Vector<BigInteger>();
		ms.add(new BigInteger("1"));
		ms.add(new BigInteger("2"));
		ms.add(new BigInteger("3"));

		CLSignature sig = CLSignature.signMessageBlock(sk, pk, ms);
		assertTrue("Signature is not valid", sig.verify(pk, ms));

		ms.set(0, new BigInteger("1337"));
		assertFalse("Signature should not verify", sig.verify(pk, ms));
	}

	@Test
	public void testCLSignatureRandomize() {
		List<BigInteger> ms = new Vector<BigInteger>();
		ms.add(new BigInteger("1"));
		ms.add(new BigInteger("2"));

		CLSignature sig = CLSignature.signMessageBlock(sk, pk, ms);
		CLSignature sig_randomized = sig.randomize(pk);

		assertTrue("Signature is not valid", sig_randomized.verify(pk, ms));
	}

	@Test
	public void testASN1Encoding1() {
		byte[] enc = Crypto.asn1Encode(new BigInteger("1"),
				new BigInteger("65"), new BigInteger("1025"));

		byte[] expected = { 0x30, 0x0D,
				0x02, 0x01, 0x03, // The number of elements is additionally encoded
				0x02, 0x01, 0x01,
				0x02, 0x01, 0x41,
				0x02, 0x02, 0x04, 0x01 };

		assertTrue(Arrays.equals(enc, expected));
	}

	@Test
	public void testCredentialHashCode() {
		IdemixCredential cred1 = new IdemixCredential(pk, attributes,
				CLSignature.signMessageBlock(sk, pk, attributes));
		IdemixCredential cred2 = new IdemixCredential(pk, attributes,
				CLSignature.signMessageBlock(sk, pk, attributes));

		assertTrue(cred1.hashCode() != 0 && cred2.hashCode() != 0 && cred1.hashCode() != cred2.hashCode());
	}

	@Test
	public void testASN1SigEncoding() {
		byte[] enc = Crypto.asn1SigEncode(new BigInteger("1"),
				new BigInteger("65"), new BigInteger("1025"));

		byte[] expected = { 0x30, 0x10, //0x10 is length of block
				0x01, 0x01, (byte) 0xff, // Boolean that indicates signature, -1 represents 0xff = true
				0x02, 0x01, 0x03, // The number of elements is additionally encoded
				0x02, 0x01, 0x01,
				0x02, 0x01, 0x41,
				0x02, 0x02, 0x04, 0x01 };

		assertTrue(Arrays.equals(enc, expected));
	}

	@Test
	public void testProofU() {
		Random rnd = new Random();
		IdemixSystemParameters params = pk.getSystemParameters();

		BigInteger context = new BigInteger(params.get_l_h(), rnd);
		BigInteger n_1 = new BigInteger(params.get_l_statzk(), rnd);
		BigInteger secret = new BigInteger(params.get_l_m(), rnd);

		CredentialBuilder cb = new CredentialBuilder(pk, null, context);
		cb.setSecret(secret);

		BigInteger U = cb.commitmentToSecret();
		ProofU proofU = cb.proveCommitment(n_1);

		assertTrue(proofU.verify(pk, context, n_1));
	}

	@Test
	public void testProofULogged() {
		BigInteger context = new BigInteger("34911926065354700717429826907189165808787187263593066036316982805908526740809");
		BigInteger n_1 = new BigInteger("724811585564063105609243");
		BigInteger c = new BigInteger("4184045431748299802782143929438273256345760339041229271411466459902660986200");
		BigInteger U = new BigInteger("53941714038323323772993715692602421894514053229231925255570480167011458936488064431963770862062871590815370913733046166911453850329862473697478794938988248741580237664467927006089054091941563143176094050444799012171081539721321786755307076274602717003792794453593019124224828904640592766190733869209960398955");
		BigInteger v_prime_response = new BigInteger("930401833442556048954810956066821001094106683380918922610147216724718347679854246682690061274042716015957693675615113399347898060611144526167949042936228868420203309360695585386210327439216083389841383395698722832808268885873389302262079691644125050748391319832394519920382663304621540520277648619992590872190274152359156399474623649137315708728792245711389032617438368799004840694779408839779419604877135070624376537994035936");
		BigInteger s_response = new BigInteger("59776396667523329313292302350278517468587673934875085337674938789292900859071752886820910103285722288747559744087880906618151651690169988337871960870439882357345503256963847251");

		ProofU proofU = new ProofU(U, c, v_prime_response, s_response);

		assertTrue(proofU.verify(pk, context, n_1));
	}

	@Test
	public void testCommitmentMessage() {
		Random rnd = new Random();
		IdemixSystemParameters params = pk.getSystemParameters();

		BigInteger context = new BigInteger(params.get_l_h(), rnd);
		BigInteger n_1 = new BigInteger(params.get_l_statzk(), rnd);
		BigInteger secret = new BigInteger(params.get_l_m(), rnd);

		CredentialBuilder cb = new CredentialBuilder(pk, null, context);
		IssueCommitmentMessage msg = cb.commitToSecretAndProve(secret, n_1);
		assertTrue(msg.getCommitmentProof().verify(pk, context, n_1));
	}

	@Test
	public void testProofS() {
		Random rnd = new Random();

		// Silly commitment, content doesn't matter for this test.
		BigInteger exponent = new BigInteger(pk.getSystemParameters().get_l_m(), rnd);
		BigInteger U = pk.getGeneratorS().modPow(exponent, pk.getModulus());

		// Silly context
		BigInteger context = new BigInteger(pk.getSystemParameters().get_l_h(), rnd);

		// Nonce (normally from the credential recipient)
		BigInteger nonce = new BigInteger(pk.getSystemParameters().get_l_statzk(), rnd);

		IdemixIssuer issuer = new IdemixIssuer(pk, sk, context);
		CLSignature sig = issuer.signCommitmentAndAttributes(U, attributes);
		ProofS proof = issuer.proveSignature(sig, nonce);

		assertTrue(proof.verify(pk, sig, issuer.getContext(), nonce));

		// Silly nonce test
		System.out.println("TEST: Will warn that hash doesn't match, that is expected");
		assertFalse(proof.verify(pk, sig, issuer.getContext(), BigInteger.TEN));

		// Silly context test
		System.out.println("TEST: Will warn that hash doesn't match, that is expected");
		assertFalse(proof.verify(pk, sig, BigInteger.TEN, nonce));
	}

	@Test
	public void testProofSLogged() {
		BigInteger context = new BigInteger("34911926065354700717429826907189165808787187263593066036316982805908526740809");
		BigInteger n_2 = new BigInteger("1424916368173409716606");

		// Signature
		BigInteger A = new BigInteger("66389313221915836241271893803869162372470096003861448260498566798077037255866372791540928160267561756794143545532118654736979223658343806335872047371607436291528588343320128898584874264796312130159695427439025355009934986408160536404163490935544221152821545871675088845781351195696518382628790514628112517886");
		BigInteger e = new BigInteger("259344723055062059907025491480697571938277889515152306249728583105665800713306759149981690559193987143012367913206299323899696942213235956742930207251663943512715842083759814664217");
		BigInteger v = new BigInteger("32427566863312925183262683355749521096160753564085736927716798279834745436154181827687524960554513739692930154573915901486008843583586162755818099731448281905764117842382407835789897633042765641230655956290191876265377547222981221260311549695231999461733778383779100992221748503727598149536948999564401095816377323412637286891625085960745712119714441272446053177642615033258689648568679017384011895908901362352242970432640019866501367925956123252426587516554347912178721773507440862343752105273189184247444400383");

		// Proof
		BigInteger c = new BigInteger("60359393410007276721785600209946099643760005142374188599509762410975853354415");
		BigInteger e_response = new BigInteger("1139627737042307991725447845798004742853435356249558932466535799661640630812910641126155269500348608443317861800376689024557774460643901450316279085276256524076388421890909312661873221470626068394945683125859434135652717426417681918932528613003921792075852313319584079881881807505760375270399908999784672094");

		CLSignature sig = new CLSignature(A, e, v);
		ProofS proof = new ProofS(c, e_response);

		assertTrue(proof.verify(pk, sig, context, n_2));
	}

	@Test
	public void testSignatureMessage() throws CredentialsException {
		Random rnd = new Random();
		IdemixSystemParameters params = pk.getSystemParameters();

		BigInteger context = new BigInteger(params.get_l_h(), rnd);
		BigInteger n_1 = new BigInteger(params.get_l_statzk(), rnd);
		BigInteger secret = new BigInteger(params.get_l_m(), rnd);

		CredentialBuilder cb = new CredentialBuilder(pk, null, context);
		IssueCommitmentMessage commit_msg = cb.commitToSecretAndProve(secret, n_1);

		IdemixIssuer issuer = new IdemixIssuer(pk, sk, context);
		issuer.issueSignature(commit_msg, attributes, n_1);
	}

	@Test
	public void fullIssuance() throws CredentialsException {
		Random rnd = new Random();
		IdemixSystemParameters params = pk.getSystemParameters();

		BigInteger context = new BigInteger(params.get_l_h(), rnd);
		BigInteger n_1 = new BigInteger(params.get_l_statzk(), rnd);
		BigInteger secret = new BigInteger(params.get_l_m(), rnd);

		CredentialBuilder cb = new CredentialBuilder(pk, attributes, context);
		IssueCommitmentMessage commit_msg = cb.commitToSecretAndProve(secret, n_1);

		IdemixIssuer issuer = new IdemixIssuer(pk, sk, context);
		IssueSignatureMessage msg = issuer.issueSignature(commit_msg, attributes, n_1);

		cb.constructCredential(msg);
	}

	@Test
	public void testShowingProof() {
		CLSignature signature = CLSignature.signMessageBlock(sk, pk, attributes);
		IdemixCredential cred = new IdemixCredential(pk, attributes, signature);
		List<Integer> disclosed = Arrays.asList(1, 2);

		Random rnd = new Random();
		IdemixSystemParameters params = pk.getSystemParameters();

		BigInteger context = new BigInteger(params.get_l_h(), rnd);
		BigInteger nonce1 = new BigInteger(params.get_l_statzk(), rnd);

		ProofD proof = cred.createDisclosureProof(disclosed, context, nonce1);

		assertTrue("Proof of disclosure should verify", proof.verify(pk, context, nonce1));
	}

	@Test
	public void testDistributedShowingProof() {
		List<BigInteger> attrs = new ArrayList<>();
		IdemixSystemParameters params = pk.getSystemParameters();
		SecureRandom srnd = new SecureRandom();

		// Generate shared private key
		BigInteger x_user = new BigInteger(params.get_l_m() - 1, srnd);
		BigInteger x_cloud = new BigInteger(params.get_l_m() - 1, srnd);
		BigInteger x = x_user.add(x_cloud);

		// Standard context and nonce
		BigInteger context = new BigInteger(params.get_l_h(), srnd);
		BigInteger nonce1 = new BigInteger(params.get_l_statzk(), srnd);

		// Generate public variant of cloud key
		List<BigInteger> public_sks = new ArrayList<>();
		BigInteger pk_cloud = pk.getGeneratorR(0).modPow(x_cloud, pk.getModulus());
		public_sks.add(pk_cloud);

		BigInteger U = pk.getGeneratorR(0).modPow(x, pk.getModulus());
		CLSignature signature = CLSignature.signMessageBlockAndCommitment(sk, pk, U, attributes);

		attrs.add(x_user);
		attrs.addAll(attributes);
		assertTrue("Distributed signature should verify",
				signature.verifyDistributed(pk, attrs, public_sks));

		IdemixDistributedCredential cred = new IdemixDistributedCredential(pk,
				public_sks, attrs, signature);
		List<Integer> disclosed = Arrays.asList(1, 2);

		// Now build a disclosure proof (we need to build using a distributed variant)

		// User side
		ProofDBuilder builder = new ProofDBuilder(cred, disclosed);
		builder.generateRandomizers();
		Commitments coms = builder.calculateCommitments();

		// Server side
		ProofPBuilder pb = new ProofPBuilder(x_cloud, pk);
		pb.generateRandomizers();
		ProofPBuilder.ProofPCommitments pcoms = pb.calculateCommitments();

		// User: Merge commitments, and calculate the challenge
		ProofPCommitmentMap cmap = new ProofPCommitmentMap();
		cmap.put(pk.getIdentifier(), pcoms);
		coms.mergeProofPCommitments(cmap);
		BigInteger challenge = coms.calculateChallenge(context, nonce1);

		// User and server finish proof
		ProofD proof = builder.createProof(challenge);
		ProofP proofp = pb.createProof(challenge);

		// User: combine proofs
		proof.mergeProofP(proofp, pk);

		assertTrue("Distributed proof of disclosure should verify",
				proof.verify(pk, context, nonce1));
	}

	@Test
	public void testDistributedIssanceAndVerify() throws CredentialsException {
		SecureRandom rnd = new SecureRandom();
		IdemixSystemParameters params = pk.getSystemParameters();

		BigInteger context = new BigInteger(params.get_l_h(), rnd);
		BigInteger n_1 = new BigInteger(params.get_l_statzk(), rnd);
		BigInteger secret = new BigInteger(params.get_l_m(), rnd);

		// Generate shared private key
		BigInteger x_user = new BigInteger(params.get_l_m() - 1, rnd);
		BigInteger x_cloud = new BigInteger(params.get_l_m() - 1, rnd);
		BigInteger x = x_user.add(x_cloud);

		// ****************
		// *** ISSUANCE ***
		// ****************

		// User: setup issuance
		DistributedCredentialBuilder cb = new DistributedCredentialBuilder(pk, attributes, context);
		cb.setSecret(x_user);
		ProofUBuilder ubuilder = new ProofUBuilder(cb);
		ubuilder.generateRandomizers();
		Commitments ucoms = ubuilder.calculateCommitments();

		// Server: start proofP
		ProofPBuilder pbuilder = new ProofPBuilder(x_cloud, pk);
		pbuilder.generateRandomizers();
		ProofPBuilder.ProofPCommitments pcoms = pbuilder.calculateCommitments();

		// User: combine ProofU and ProofP commitments
		ProofPCommitmentMap cmap = new ProofPCommitmentMap();
		cmap.put(pk.getIdentifier(), pcoms);
		ucoms.mergeProofPCommitments(cmap);
		BigInteger challenge = ucoms.calculateChallenge(context, n_1);

		// User and server finish proof
		ProofU proofu = ubuilder.createProof(challenge);
		ProofP proofp = pbuilder.createProof(challenge);

		// User: combine proofs, create issuer message
		proofu.mergeProofP(proofp, pk);
		assertTrue("Combined ProofU should be a valid proof", proofu.verify(pk, context, n_1));

		// Update state of DistributedCredentialBuilder
		cb.addPublicSK(proofp.getP());

		IssueCommitmentMessage commit_msg = new IssueCommitmentMessage(proofu, cb.getNonce2());

		IdemixIssuer issuer = new IdemixIssuer(pk, sk, context);
		IssueSignatureMessage msg = issuer.issueSignature(commit_msg, attributes, n_1);
		IdemixDistributedCredential cred = cb.constructCredential(msg);

		// ******************
		// *** DISCLOSURE ***
		// ******************
		List<Integer> disclosed = Arrays.asList(1, 2);
		BigInteger nonce1 = new BigInteger(params.get_l_statzk(), rnd);

		// User side
		ProofDBuilder dbuilder = new ProofDBuilder(cred, disclosed);
		dbuilder.generateRandomizers();
		Commitments dcoms = dbuilder.calculateCommitments();

		// Server side (reusing ProofPBuilder)
		pbuilder.generateRandomizers();
		pcoms = pbuilder.calculateCommitments();

		// User: Merge commitments, and calculate the challenge
		cmap.put(pk.getIdentifier(), pcoms);
		dcoms.mergeProofPCommitments(cmap);
		challenge = dcoms.calculateChallenge(context, nonce1);

		// User and server finish proof
		ProofD proofd = dbuilder.createProof(challenge);
		proofp = pbuilder.createProof(challenge);

		// User: combine proofs
		proofd.mergeProofP(proofp, pk);

		assertTrue("Distributed proof of disclosure should verify",
				proofd.verify(pk, context, nonce1));
	}

	@Test
	public void testCombinedShowingProof() {
		CLSignature signature1 = CLSignature.signMessageBlock(sk, pk, attributes);
		IdemixCredential cred1 = new IdemixCredential(pk, attributes, signature1);

		CLSignature signature2 = CLSignature.signMessageBlock(sk, pk, attributes);
		IdemixCredential cred2 = new IdemixCredential(pk, attributes, signature2);

		Random rnd = new Random();
		IdemixSystemParameters params = pk.getSystemParameters();
		BigInteger context = new BigInteger(params.get_l_h(), rnd);
		BigInteger nonce1 = new BigInteger(params.get_l_statzk(), rnd);

		ProofList collection = new ProofListBuilder(context, nonce1)
				.addProofD(cred1, Arrays.asList(1, 2))
				.addProofD(cred2, Arrays.asList(1, 3))
				.build();

		assertTrue("Combined disclosure proofs should verify", collection.verify(context, nonce1, true));
	}

	@Test
	public void testCombinedDistributedShowingProof() throws InfoException, KeyException {
		IssuerIdentifier pbdf = new IssuerIdentifier("pbdf.pbdf");
		IdemixPublicKey pk = IdemixKeyStore.getInstance().getPublicKey(pbdf, 0);
		IdemixSecretKey sk = IdemixKeyStore.getInstance().getSecretKey(pbdf, 0);

		IdemixSystemParameters params = pk.getSystemParameters();
		SecureRandom srnd = new SecureRandom();

		// Generate shared private key
		BigInteger x_user = new BigInteger(params.get_l_m() - 1, srnd);
		BigInteger x_cloud = new BigInteger(params.get_l_m() - 1, srnd);
		BigInteger x = x_user.add(x_cloud);

		// Standard context and nonce
		BigInteger context = new BigInteger(params.get_l_h(), srnd);
		BigInteger nonce1 = new BigInteger(params.get_l_statzk(), srnd);

		// Generate public variant of cloud key
		List<BigInteger> public_sks = new ArrayList<>();
		BigInteger pk_cloud = pk.getGeneratorR(0).modPow(x_cloud, pk.getModulus());
		public_sks.add(pk_cloud);

		List<BigInteger> attrs = new ArrayList<>();
		attrs.add(x_user);
		attrs.addAll(attributes);

		BigInteger U = pk.getGeneratorR(0).modPow(x, pk.getModulus());
		CLSignature signature1 = CLSignature.signMessageBlockAndCommitment(sk, pk, U, attributes);
		IdemixDistributedCredential cred1 = new IdemixDistributedCredential(pk,
				public_sks, attrs, signature1);

		CLSignature signature2 = CLSignature.signMessageBlockAndCommitment(sk, pk, U, attributes);
		IdemixDistributedCredential cred2 = new IdemixDistributedCredential(pk,
				public_sks, attrs, signature2);

		// User side
		ProofListBuilder builder = new ProofListBuilder(context, nonce1)
				.addProofD(cred1, Arrays.asList(1, 2))
				.addProofD(cred2, Arrays.asList(1, 3));
		builder.generateRandomizers();
		List<PublicKeyIdentifier> pkids = builder.getPublicKeyIdentifiers();

		// Server side
		ProofPListBuilder pbuilder = new ProofPListBuilder(pkids, x_cloud);
		pbuilder.generateRandomizers();
		ProofPCommitmentMap plistcom = pbuilder.calculateCommitments();

		// User side: merge commitments, calculate challenge
		ProofListBuilder.Commitment com = builder.calculateCommitments();
		com.mergeProofPCommitments(plistcom);
		BigInteger challenge = com.calculateChallenge(context, nonce1);

		// Server & User side: calculate responses
		ProofP proofp = pbuilder.build(challenge);
		ProofList collection = builder.createProofList(challenge, proofp);

		assertTrue("Combined disclosure proofs should verify",
				collection.verify(context, nonce1, true));
	}

	@Test
	public void testSignature() {
		CLSignature signature1 = CLSignature.signMessageBlock(sk, pk, attributes);
		IdemixCredential cred1 = new IdemixCredential(pk, attributes, signature1);

		CLSignature signature2 = CLSignature.signMessageBlock(sk, pk, attributes);
		IdemixCredential cred2 = new IdemixCredential(pk, attributes, signature2);

		Random rnd = new Random();
		IdemixSystemParameters params = pk.getSystemParameters();
		BigInteger context = new BigInteger(params.get_l_h(), rnd);
		BigInteger nonce1 = new BigInteger(params.get_l_statzk(), rnd);

		boolean isSig = true;
		ProofList collection = new ProofListBuilder(context, nonce1, isSig)
				.addProofD(cred1, Arrays.asList(1, 2))
				.addProofD(cred2, Arrays.asList(1, 3))
				.build();

		assertTrue("Combined signature should verify", collection.verify(context, nonce1, true));
	}

	/**
	 * Test if nonce used for signature cannot be reused in a disclosureproof
	 */
	@Test
	public void testDomainSeparation() {
		CLSignature signature1 = CLSignature.signMessageBlock(sk, pk, attributes);
		IdemixCredential cred1 = new IdemixCredential(pk, attributes, signature1);

		CLSignature signature2 = CLSignature.signMessageBlock(sk, pk, attributes);
		IdemixCredential cred2 = new IdemixCredential(pk, attributes, signature2);

		Random rnd = new Random();
		IdemixSystemParameters params = pk.getSystemParameters();
		BigInteger context = new BigInteger(params.get_l_h(), rnd);
		BigInteger nonce1 = new BigInteger(params.get_l_statzk(), rnd);

		// Create an IRMA signature
		boolean isSig = true;
		ProofList collection = new ProofListBuilder(context, nonce1, isSig)
				.addProofD(cred1, Arrays.asList(1, 2))
				.addProofD(cred2, Arrays.asList(1, 3))
				.build();

		// Make sure we're verifying this signature as disclosure proof
		collection.setSig(false);

		assertTrue("Combined signature should NOT verify as disclosure proof", !collection
				.verify(context, nonce1, true));
	}

	@Test
	public void testShowingProofLogged() {
		BigInteger nonce1 = new BigInteger("356168310758183945030882");
		BigInteger context = new BigInteger("59317469690166962413036802769129097120995929488116634148207386064523180296869");

		BigInteger c = new BigInteger("92405256824458923934294175762399873039847432841647909261385804859937404075570");
		BigInteger A = new BigInteger("66467922530801909191099602528137141713616048447732479189179865050384832390931230033112445547628606292639430708552418462959456337530534055700746138057512598497120682196611341962749384189596253759402224308748002860890211498962735924481685975488607793795169788837476493253297353146422154392391732925567178805607");
		BigInteger e_response = new BigInteger("44022597110989879399510333540268555303613344906583879371531630680320900347240418258690335759375210734514869637566864349585531295946323809");
		BigInteger v_response = new BigInteger("26326301830460880582628741955953428491879823201714737915103888193625032953131902593859116395461541557845953939714765660366793552012359281854190756504190064959818584175057775414324351414234450208391534497565506441579960808534266557458251190151268682500197950418141493586125049371381626638554299245282498637246703583102656876690825544275995631773170789236920674341621008537679924624747222821679128060382072191284077393034573357698475000667180794116538132628586533009732462826119381931507809052573496513689222244701991737191273263148163121236326525677935993049602389899306007664212328515456044738278420");

		HashMap<Integer, BigInteger> a_responses = new HashMap<Integer, BigInteger>();
		a_responses.put(0, new BigInteger("55247823867049193571627241180110605447453053126985891402640532123848293918217459966028364637387399903283634100097425890971508590427350301193682412170041146212137866279677802531"));
		HashMap<Integer, BigInteger> a_disclosed = new HashMap<Integer, BigInteger>();
		a_disclosed.put(1,  new BigInteger("1100598411265"));
		a_disclosed.put(2,  new BigInteger("43098508374675488371040117572049064979183030441504364"));
		a_disclosed.put(3,  new BigInteger("4919409929397552454"));

		ProofD proof = new ProofD(c, A, e_response, v_response, a_responses, a_disclosed);

		assertTrue("Proof of disclosure should verify", proof.verify(pk, context, nonce1));
	}

	@Test
	public void fullIssuanceAndShowing() throws CredentialsException {
		Random rnd = new Random();
		IdemixSystemParameters params = pk.getSystemParameters();

		BigInteger context = new BigInteger(params.get_l_h(), rnd);
		BigInteger n_1 = new BigInteger(params.get_l_statzk(), rnd);
		BigInteger secret = new BigInteger(params.get_l_m(), rnd);

		// Issuance
		CredentialBuilder cb = new CredentialBuilder(pk, attributes, context);
		IdemixIssuer issuer = new IdemixIssuer(pk, sk, context);

		IssueCommitmentMessage commit_msg = cb.commitToSecretAndProve(secret, n_1);
		IssueSignatureMessage msg = issuer.issueSignature(commit_msg, attributes, n_1);
		IdemixCredential cred = cb.constructCredential(msg);

		// Showing
		n_1 = new BigInteger(params.get_l_statzk(), rnd);
		List<Integer> disclosed = Arrays.asList(1, 2);

		ProofD proof = cred.createDisclosureProof(disclosed, context, n_1);
		assertTrue("Proof of disclosure should verify", proof.verify(pk, context, n_1));
	}

	@Test
	public void testFullBoundIssuanceAndShowing() throws CredentialsException {
		// Initialize parameters
		Random rnd = new Random();
		IdemixSystemParameters params = pk.getSystemParameters();
		BigInteger context = new BigInteger(params.get_l_h(), rnd);
		BigInteger n_1 = new BigInteger(params.get_l_statzk(), rnd);

		// Create credential that will be shown during issuing
		CLSignature signature1 = CLSignature.signMessageBlock(sk, pk, attributes);
		IdemixCredential cred1 = new IdemixCredential(pk, attributes, signature1);

		// Initialize builder and issuer
		CredentialBuilder cb = new CredentialBuilder(pk, attributes, context);
		IdemixIssuer issuer = new IdemixIssuer(pk, sk, context);

		// Do the issuing. Note that we do not check here if the commit_msg contains the required disclosure proofs
		// (although it does); that should be done at a higher level.
		ProofListBuilder builder = new ProofListBuilder(context, n_1)
				.addProofD(cred1, Arrays.asList(1, 2))
				.addCredentialBuilder(cb);
		IssueCommitmentMessage commit_msg = new IssueCommitmentMessage(builder.build(), cb.getNonce2());
		IssueSignatureMessage msg = issuer.issueSignature(commit_msg, attributes, n_1);
		IdemixCredential cred2 = cb.constructCredential(msg);

		// Showing
		n_1 = new BigInteger(params.get_l_statzk(), rnd);
		List<Integer> disclosed = Arrays.asList(1, 3);
		ProofD proof = cred2.createDisclosureProof(disclosed, context, n_1);
		assertTrue("Proof of disclosure should verify", proof.verify(pk, context, n_1));
	}

	@Test
	public void testDistributedBoundIssanceAndVerify() throws CredentialsException, InfoException, KeyException {
		IssuerIdentifier pbdf = new IssuerIdentifier("pbdf.pbdf");
		IdemixPublicKey pk = IdemixKeyStore.getInstance().getPublicKey(pbdf, 0);
		IdemixSecretKey sk = IdemixKeyStore.getInstance().getSecretKey(pbdf, 0);

		SecureRandom rnd = new SecureRandom();
		IdemixSystemParameters params = pk.getSystemParameters();

		BigInteger context = new BigInteger(params.get_l_h(), rnd);
		BigInteger n_1 = new BigInteger(params.get_l_statzk(), rnd);

		// Generate shared private key
		BigInteger x_user = new BigInteger(params.get_l_m() - 1, rnd);
		BigInteger x_cloud = new BigInteger(params.get_l_m() - 1, rnd);
		BigInteger x = x_user.add(x_cloud);

		// ************************************
		// *** Generate existing credential ***
		// ************************************

		// Generate public variant of cloud key
		List<BigInteger> public_sks = new ArrayList<>();
		BigInteger pk_cloud = pk.getGeneratorR(0).modPow(x_cloud, pk.getModulus());
		public_sks.add(pk_cloud);

		List<BigInteger> attrs = new ArrayList<>();
		attrs.add(x_user);
		attrs.addAll(attributes);

		BigInteger U = pk.getGeneratorR(0).modPow(x, pk.getModulus());
		CLSignature signature1 = CLSignature.signMessageBlockAndCommitment(sk, pk, U, attributes);
		IdemixDistributedCredential cred1 = new IdemixDistributedCredential(pk,
				public_sks, attrs, signature1);

		// ****************
		// *** ISSUANCE ***
		// ****************

		// User: setup issuance
		DistributedCredentialBuilder cb = new DistributedCredentialBuilder(pk, attributes, context);
		cb.setSecret(x_user);

		// User side
		ProofListBuilder builder = new ProofListBuilder(context, n_1)
				.addProofD(cred1, Arrays.asList(1, 2))
				.addCredentialBuilder(cb);
		builder.generateRandomizers();
		List<PublicKeyIdentifier> pkids = builder.getPublicKeyIdentifiers();

		// Server side
		ProofPListBuilder pbuilder = new ProofPListBuilder(pkids, x_cloud);
		pbuilder.generateRandomizers();
		ProofPCommitmentMap plistcom = pbuilder.calculateCommitments();

		// User side: merge commitments, calculate challenge
		ProofListBuilder.Commitment com = builder.calculateCommitments();
		com.mergeProofPCommitments(plistcom);
		BigInteger challenge = com.calculateChallenge(context, n_1);

		// Server & User side: calculate responses
		ProofP proofp = pbuilder.build(challenge);
		ProofList collection = builder.createProofList(challenge, proofp);

		assertTrue("ProofList should verify", collection.verify(context, n_1, true));

		// Update state of DistributedCredentialBuilder
		cb.addPublicSK(plistcom);

		IssueCommitmentMessage commit_msg = new IssueCommitmentMessage(collection, cb.getNonce2());

		IdemixIssuer issuer = new IdemixIssuer(pk, sk, context);
		IssueSignatureMessage msg = issuer.issueSignature(commit_msg, attributes, n_1);
		IdemixDistributedCredential cred2 = cb.constructCredential(msg);

		// ******************
		// *** DISCLOSURE ***
		// ******************
		List<Integer> disclosed = Arrays.asList(1, 2);
		BigInteger nonce1 = new BigInteger(params.get_l_statzk(), rnd);

		// User side
		ProofDBuilder dbuilder = new ProofDBuilder(cred2, disclosed);
		dbuilder.generateRandomizers();
		Commitments dcoms = dbuilder.calculateCommitments();

		// Server side
		ProofPBuilder simplepbuilder = new ProofPBuilder(x_cloud, pk);
		simplepbuilder.generateRandomizers();
		ProofPBuilder.ProofPCommitments pcoms = simplepbuilder.calculateCommitments();

		// User: Merge commitments, and calculate the challenge
		ProofPCommitmentMap cmap = new ProofPCommitmentMap();
		cmap.put(pk.getIdentifier(), pcoms);
		dcoms.mergeProofPCommitments(cmap);
		challenge = dcoms.calculateChallenge(context, nonce1);

		// User and server finish proof
		ProofD proofd = dbuilder.createProof(challenge);
		proofp = simplepbuilder.createProof(challenge);

		// User: combine proofs
		proofd.mergeProofP(proofp, pk);

		assertTrue("Distributed proof of disclosure should verify",
				proofd.verify(pk, context, nonce1));
	}

	@Test
	public void testWronglyBoundProofs() throws CredentialsException {
		CLSignature signature1 = CLSignature.signMessageBlock(sk, pk, attributes);
		IdemixCredential cred1 = new IdemixCredential(pk, attributes, signature1);

		// Attributes for our second credential, with a different secret key (i.e. the first attribute)
		List<BigInteger> attributes2 = Arrays.asList(
				new BigInteger(1, "alpha".getBytes()),
				new BigInteger(1, "beta".getBytes()),
				new BigInteger(1, "gamma".getBytes()),
				new BigInteger(1, "delta".getBytes()));
		CLSignature signature2 = CLSignature.signMessageBlock(sk, pk, attributes2);
		IdemixCredential cred2 = new IdemixCredential(pk, attributes, signature2);

		Random rnd = new Random();
		IdemixSystemParameters params = pk.getSystemParameters();
		BigInteger context = new BigInteger(params.get_l_h(), rnd);
		BigInteger nonce1 = new BigInteger(params.get_l_statzk(), rnd);

		ProofList proofs = new ProofListBuilder(context, nonce1)
				.addProofD(cred1, Arrays.asList(1, 2))
				.addProofD(cred2, Arrays.asList(1, 3))
				.build();

		// The proof collection should be invalid both as bound and as unbound proofs
		System.out.println("TEST: Will warn that hash doesn't match, that is expected");
		assertTrue("Combined disclosure proofs should not verify", !proofs.verify(context, nonce1, false));
		assertTrue("Combined disclosure proofs should not verify", !proofs.verify(context, nonce1, true));
	}

	/**
	 * We construct one disclosure proof using a ProofListBuilder, and see if it verifies as a normal unbound
	 * proof.
	 */
	@Test
	public void testBoundDisclosureProofBackwardsCompatible() {
		CLSignature signature = CLSignature.signMessageBlock(sk, pk, attributes);
		IdemixCredential cred = new IdemixCredential(pk, attributes, signature);
		List<Integer> disclosed = Arrays.asList(1, 2);

		Random rnd = new Random();
		IdemixSystemParameters params = pk.getSystemParameters();

		BigInteger context = new BigInteger(params.get_l_h(), rnd);
		BigInteger nonce1 = new BigInteger(params.get_l_statzk(), rnd);
		ProofD proof = (ProofD) new ProofListBuilder(context, nonce1)
				.addProofD(cred, Arrays.asList(1, 2))
				.build()
				.get(0);

		assertTrue("Proof of disclosure should verify", proof.verify(pk, context, nonce1));
	}

	/**
	 * We construct a proof of knowledge of the secret key and v_prime using a ProofListBuilder, and see if it
	 * verifies as a normal unbound proof
	 */
	@Test
	public void testBoundProofUBackwardsCompatible() throws CredentialsException {
		// Initialize parameters
		Random rnd = new Random();
		IdemixSystemParameters params = pk.getSystemParameters();
		BigInteger context = new BigInteger(params.get_l_h(), rnd);
		BigInteger n_1 = new BigInteger(params.get_l_statzk(), rnd);

		// Initialize builder and issuer
		CredentialBuilder cb = new CredentialBuilder(pk, attributes, context);
		IdemixIssuer issuer = new IdemixIssuer(pk, sk, context);

		// Create the proofU using the ProofListBuilder, extract it, and put it in a vanilla IssueCommitmentMessage
		ProofListBuilder builder = new ProofListBuilder(context, n_1).addCredentialBuilder(cb);
		IssueCommitmentMessage commit_msg = new IssueCommitmentMessage(builder.build(), cb.getNonce2());
		ProofU proofU = commit_msg.getCombinedProofs().getProofU();
		commit_msg = new IssueCommitmentMessage(proofU, commit_msg.getNonce2());

		// Do the issuing
		IssueSignatureMessage msg = issuer.issueSignature(commit_msg, attributes, n_1);
		IdemixCredential cred = cb.constructCredential(msg);

		// Showing
		n_1 = new BigInteger(params.get_l_statzk(), rnd);
		List<Integer> disclosed = Arrays.asList(1, 3);
		ProofD proof = cred.createDisclosureProof(disclosed, context, n_1);
		assertTrue("Proof of disclosure should verify", proof.verify(pk, context, n_1));
	}

	@Test
	public void testBigAttributes() throws Exception {
		String attr = "This is a very long attribute: its size of 132 bytes exceeds the maximum message length of all currently supported public key sizes.";
		List<BigInteger> attributes = Arrays.asList(
				new BigInteger(1, "alpha".getBytes()),
				new BigInteger(1, "beta".getBytes()),
				new BigInteger(1, attr.getBytes()));
		CLSignature signature = CLSignature.signMessageBlock(sk, pk, attributes);
		IdemixCredential cred = new IdemixCredential(pk, attributes, signature);

		// Don't disclose large attribute
		assertTrue(
			cred.createDisclosureProof(Collections.singletonList(1), BigInteger.TEN, BigInteger.TEN)
					.verify(pk, BigInteger.TEN, BigInteger.TEN)
		);
		// Disclose large attribute
		assertTrue(
				cred.createDisclosureProof(Collections.singletonList(2), BigInteger.TEN, BigInteger.TEN)
						.verify(pk, BigInteger.TEN, BigInteger.TEN)
		);
	}
}