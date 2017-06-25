# Credentials Idemix

The Credentials Idemix library implements IRMA credentials at a mathematical level.

To actually communicate to an IRMA client such as a smart card or the [IRMA Android app](https://github.com/credentials/irma_android_cardemu), you would need a library such as [idemix_terminal](https://github.com/credentials/idemix_terminal/) or [irma_api_common](https://github.com/credentials/irma_api_common/), respectively, so normally you will want to use one of those libaries instead of including this one directly.

This library itself works in two layers. The first layer implements the bare Idemix credentials. However, IRMA is more than just Idemix credentials, in particular we always include a validity date and the credential's semantics. We validate this in an IRMA layer on top of the bare Idemix credentials.

## Prerequisites

This library has the following dependencies.  All these dependencies will be automatically downloaded by gradle when building or installing the library.

External dependencies:

 * BouncyCastle: bcprov-jdk15on

Internal dependencies:

 * [credentials_api](https://github.com/credentials/credentials_api), the abstract IRMA credentials API

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
