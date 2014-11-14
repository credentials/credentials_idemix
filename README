# Credentials Idemix

The Credentials Idemix API implements the high level credentials/credentials_api. It offers easy access to the credentials that are described in credentials/irma_configuration. For all these examples we assume that you obtained a `CardService` to talk to the card. You could for example use:

```Java
CardService cs = new TerminalCardService(
    TerminalFactory.getDefault().terminals().list().get(0));
```

(Error handling omitted).  After setting up you can run:

```Java
VerifyCredentialInformation vci = new VerifyCredentialInformation(
    "Surfnet", "rootNone");
IdemixVerifySpecification vspec = vci.getIdemixVerifySpecification();
Attributes attr = new IdemixCredentials(cs).verify(vspec);
```

to verify the Surfnet root credential, while keeping all attributes hidden. When the credential verified, `attr` contains the revealed attributes (possibly represented by an empty list), otherwise `attr` is `null`. Similarly, a Surfnet root credential can be issued as follows: 

```Java
// Retrieve the issue specification and get the Issuer's private key
IssueCredentialInformation ici = new IssueCredentialInformation("Surfnet", "root");
IdemixIssueSpecification spec = ici.getIdemixIssueSpecification();
IdemixPrivateKey isk = ici.getIdemixPrivateKey();

// Setup the attributes that will be issued to the card
Attributes attributes = new Attributes();
attributes.add("userID", "s1234567@student.ru.nl".getBytes());
attributes.add("securityHash", "DEADBEEF".getBytes());

// Setup a connection and send pin
IdemixService is = new IdemixService(TestSetup.getCardService());
IdemixCredentials ic = new IdemixCredentials(is);
ic.connect();
is.sendPin({0x30, 0x30, 0x30, 0x30}); // TODO: Change to send the correct pin.

// Issue the credential
ic.issue(spec, isk, attributes, null); // null indicates default expiry
```

### Asynchronous use

In some scenario's (like when using a web server) you don't have direct access to a card reader. The API offers a lower-level asynchronous access point, where you get the APDU that need to be send to the smart card, and can handle them in any way that you like.

First, we select the credential as before

```Java
VerifyCredentialInformation vci = new VerifyCredentialInformation("Surfnet", "rootNone");
IdemixVerifySpecification vspec = vci.getIdemixVerifySpecification();
IdemixCredentials ic = new IdemixCredentials(null);
````

To keep this example simple, we use the regular `IdemixService` to send the commands to the card. Replace this with whatever suits your application best.

```Java
// Open channel to card
IdemixService service = new IdemixService(cs);
service.open();
```

First, we select the applet and process the resulting version number.

```Java
ProtocolResponse select_response = service.execute(
IdemixSmartcard.selectApplicationCommand);
CardVersion cv = new CardVersion(select_response.getData());
vspec.setCardVersion(cv);
```

To verify a credential the verifier generates a nonce, before it generates the commands to send to the card. This nonce is also necessary to verify the responses. We'll want to store this nonce, for when the responses come in.

```Java
Nonce nonce = ic.generateNonce(vspec);
```

Next, we generate the actual verification commands, and send them to the card.

```Java
ProtocolCommands commands = ic.requestProofCommands(vspec, nonce);
ProtocolResponses responses = service.execute(commands);
```
                
Finally, we verify the attributes. Here we use the nonce that we generated earlier.

```Java
Attributes attr = ic.verifyProofResponses(vspec, nonce, responses);
```

## Prerequisites

This library has the following dependencies.  All these dependencies will be automatically downloaded by gradle when building or installing the library (except for `cert-cvc` which is included).

External dependencies:

 * BouncyCastle: bcprov-jdk15on
 * Cert-CVC
 * Idemix Library
 * Scuba: scuba_smartcards

Internal dependencies:

 * credentials/credentials_api, The abstract IRMA credentials API
 * credentials/idemix_terminal, The IRMA idemix card terminal library

For running the tests:

 * JUnit,  (>= 4.8), the Java unit-testing library
 * Scuba: scuba_sc_j2se

The build system depends on gradle version at least 1.12.

## Building

Run
    
    gradle build

## Installing

You can install the library to your local maven repository by running

    gradle install

It will then be found by other gradle build scripts.


## Using the library

Before using the library you need to setup `irma_configuration`.

### irma_configuration

Download or link the `irma_configuration` project to a location within your tree. In particular the tests below assume that `irma_configuration` is placed in the root of this project.

See the credentials/irma_configuration project for the specifics. Remember that you can check out a different branch to get a different set of credentials and corresponding keys. In particular, the demo branch contains keys for all the issuers as well, thus making it very easy to test and develop applications.

## Issueing/Verifying/Deleting credentials

You can use gradle to quickly get some credentials on your card. This assumes that you have linked/checked `irma_configuration` in the root of this project (and have the necessary keys for issuing, for example by using the demo branch).

    gradle test --tests "*issue*"

You can use the tests to verify the same credentials or remove them

    gradle test --tests "*verify*"
    gradle test --tests "*remove*"

You can use this format to specify any tests. For example you can just issue yourself a root credential:

    gradle test --tests "*issueRootCredential"

If you desire more verbose output, you can also decide to pass the `-Pverbose` flag to see all the output generated by the tests.

    gradle -Pverbose test --tests "*verifyRootCredentialAll"
