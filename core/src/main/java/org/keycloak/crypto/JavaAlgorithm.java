/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.crypto;

public class JavaAlgorithm {

    public static final String RS256 = "SHA256withRSA";
    public static final String RS384 = "SHA384withRSA";
    public static final String RS512 = "SHA512withRSA";
    public static final String HS256 = "HMACSHA256";
    public static final String HS384 = "HMACSHA384";
    public static final String HS512 = "HMACSHA512";
    public static final String ES256 = "SHA256withECDSA";
    public static final String ES384 = "SHA384withECDSA";
    public static final String ES512 = "SHA512withECDSA";
    public static final String PS256 = "SHA256withRSAandMGF1";
    public static final String PS384 = "SHA384withRSAandMGF1";
    public static final String PS512 = "SHA512withRSAandMGF1";
    public static final String AES = "AES";

    public static final String SHA256 = "SHA-256";
    public static final String SHA384 = "SHA-384";
    public static final String SHA512 = "SHA-512";

    public static String getJavaAlgorithm(String algorithm) {
        if (Algorithm.RS256.equals(algorithm)) {
			return RS256;
		} else if (Algorithm.RS384.equals(algorithm)) {
			return RS384;
		} else if (Algorithm.RS512.equals(algorithm)) {
			return RS512;
		} else if (Algorithm.HS256.equals(algorithm)) {
			return HS256;
		} else if (Algorithm.HS384.equals(algorithm)) {
			return HS384;
		} else if (Algorithm.HS512.equals(algorithm)) {
			return HS512;
		} else if (Algorithm.ES256.equals(algorithm)) {
			return ES256;
		} else if (Algorithm.ES384.equals(algorithm)) {
			return ES384;
		} else if (Algorithm.ES512.equals(algorithm)) {
			return ES512;
		} else if (Algorithm.PS256.equals(algorithm)) {
			return PS256;
		} else if (Algorithm.PS384.equals(algorithm)) {
			return PS384;
		} else if (Algorithm.PS512.equals(algorithm)) {
			return PS512;
		} else if (Algorithm.AES.equals(algorithm)) {
			return AES;
		} else {
			throw new IllegalArgumentException("Unknown algorithm " + algorithm);
		}
    }


    public static String getJavaAlgorithmForHash(String algorithm) {
        if (Algorithm.RS256.equals(algorithm)) {
			return SHA256;
		} else if (Algorithm.RS384.equals(algorithm)) {
			return SHA384;
		} else if (Algorithm.RS512.equals(algorithm)) {
			return SHA512;
		} else if (Algorithm.HS256.equals(algorithm)) {
			return SHA256;
		} else if (Algorithm.HS384.equals(algorithm)) {
			return SHA384;
		} else if (Algorithm.HS512.equals(algorithm)) {
			return SHA512;
		} else if (Algorithm.ES256.equals(algorithm)) {
			return SHA256;
		} else if (Algorithm.ES384.equals(algorithm)) {
			return SHA384;
		} else if (Algorithm.ES512.equals(algorithm)) {
			return SHA512;
		} else if (Algorithm.PS256.equals(algorithm)) {
			return SHA256;
		} else if (Algorithm.PS384.equals(algorithm)) {
			return SHA384;
		} else if (Algorithm.PS512.equals(algorithm)) {
			return SHA512;
		} else if (Algorithm.AES.equals(algorithm)) {
			return AES;
		} else {
			throw new IllegalArgumentException("Unknown algorithm " + algorithm);
		}
    }

}
