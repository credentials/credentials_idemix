# Credentials Idemix

The Credentials Idemix library implements IRMA credentials at a mathematical level. You need the [idemix_terminal](https://github.com/credentials/idemix_terminal) to use this library to actually communicate with an IRMA card. Normally, you will always use `idemix_terminal` and not rely on this library directly.

This library itself works in two layers. The first layer implements the bare Idemix credentials. However, IRMA is more than just Idemix credentials, in particular we always include a validity date and the credential's semantics. We validate this in an IRMA layer on top of the bare Idemix credentials.

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

Gradle will take care of the transitive dependencies.

For running the tests:

 * JUnit,  (>= 4.8), the Java unit-testing library

The build system depends on gradle version at least 1.12.

## Building

Run
    
    gradle build

## Installing

You can install the library to your local maven repository by running

    gradle install

It will then be found by other gradle build scripts.

## Testing

Gradle automatically runs the tests if the code has changed. If you want to force them to rerun use

    gradle cleanTest test

## Using the library

Before using the library you need to setup `irma_configuration`.

### irma_configuration

Download or link the `irma_configuration` project to a location within your tree. In particular the tests below assume that `irma_configuration` is placed in the root of this project.

See the credentials/irma_configuration project for the specifics. Remember that you can check out a different branch to get a different set of credentials and corresponding keys. In particular, the demo branch contains keys for all the issuers as well, thus making it very easy to test and develop applications.
