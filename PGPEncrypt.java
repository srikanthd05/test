 
/*
 * * Copyright ©  2018 Software AG, Darmstadt, Germany and/or its licensors
 * *
 * * SPDX-License-Identifier: Apache-2.0
 * *
 * * Licensed under the Apache License, Version 2.0 (the "License");
 * * you may not use this file except in compliance with the License.
 * * You may obtain a copy of the License at
 * *
 * * http://www.apache.org/licenses/LICENSE-2.0
 * *
 * *  Unless required by applicable law or agreed to in writing, software
 * *  distributed under the License is distributed on an "AS IS" BASIS,
 * *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * *  See the License for the specific language governing permissions and
 * *  limitations under the License.                                                            
 * *
 * */
package com.softwareag.pgp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.Iterator;
import java.util.Stack;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

/**
 * This class provides functionality for encrypting and optionally signing data
 * using public and private keys.
 */

public class PGPEncrypt {
	
	/**
     * The default block size
     */
	
	private static final int BLOCK = 8192;
	
	static {
        // Initialize PGP provider
        PGPInit.init();
    }
	
	/**
     * Encrypts plain data from an input stream and writes cipher data to an
     * output stream. If the useArmor flag is set, the cipher data is written to
     * the output stream as an ASCII text. If not set, the output data is
     * written as raw bytes.
     * 
     * @param plain An intput stream with plain data
     * @param cipher An output stream with cipher data
     * @param key A PGP public key object
     * @param algorithm The symmetric key encryption algorithm
     * @param useArmor Flag for encoding output to ASCII
     * @throws PGPException If the message cannot be encrypted
     * @throws IOException If the streams cannot be accessed
     * @throws NoSuchProviderException If the keys or algorithms are not supported
     */
	
	public static void encrypt(InputStream plain, OutputStream cipher,
            PGPPublicKey key, int algorithm, boolean useArmor, String filename)
            throws PGPException, IOException, NoSuchProviderException {

        // Stream stack
        Stack<OutputStream> streams = new Stack<OutputStream>();

        // Create armored output stream
        OutputStream out = cipher;
        if (useArmor) {
            out = new ArmoredOutputStream(cipher);
        }

        // Create encrypting stream
        streams.push(out);
        
        PGPEncryptedDataGenerator encrypt = new PGPEncryptedDataGenerator(new JcePGPDataEncryptorBuilder(algorithm)
                .setSecureRandom(new SecureRandom()).setProvider(PGPInit.PROVIDER));
                
        
        //PGPEncryptedDataGenerator encrypt = new PGPEncryptedDataGenerator(
               // algorithm, true, new SecureRandom(), PGPInit.PROVIDER);
        encrypt.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(key));
        out = encrypt.open(out, new byte[BLOCK]);

        // Create compressed stream
        streams.push(out);
        PGPCompressedDataGenerator compress = new PGPCompressedDataGenerator(
                PGPCompressedDataGenerator.ZIP);
        out = compress.open(out);

        // Create literal stream
        streams.push(out);
        PGPLiteralDataGenerator literal = new PGPLiteralDataGenerator();
        out = literal.open(out, PGPLiteralData.BINARY, PGPLiteralData.CONSOLE,
                plain.available(), PGPLiteralData.NOW);

        // Write plain to encrypted stream");
        byte[] buffer = new byte[BLOCK];
        while (plain.available() > 0) {
            int read = plain.read(buffer);
            out.write(buffer, 0, read);
        }

        // Close all streams
        while (!streams.isEmpty()) {
            try {
                OutputStream next = streams.pop();
                next.flush();
                next.close();
            } catch (Exception e) {
            }
        }
        cipher.flush();
    }
	

}