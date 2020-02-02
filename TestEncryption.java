package com.softwareag.pgp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.Charset;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;

public class TestEncryption {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		
		PGPPublicKeyRingCollection ringPub = null;
		PGPPublicKey keyPub = null;
		String plainText = "This test is for first encryption";
		
		String path = "C:\\Users\\sravs\\Desktop\\PGP\\newPublic.asc";
		String alg = "RSA";
		try{
			 ringPub = PGPKeyReader.readPublicKeyRing(path);
			 System.out.println(ringPub.size());
			 //System.out.println(ringPub.)
			 keyPub = PGPKeyReader.readPublicKey(ringPub, PGPInit.getKeyExchangeAlgorithm(alg));
			 System.out.println( "publicKey: "+ keyPub);
			 System.out.println( "keyId: "+ String.valueOf(keyPub.getKeyID()));
			 System.out.println( "algorithm: "+ String.valueOf(keyPub.getAlgorithm()));
			 System.out.println( "bitStrength: "+ String.valueOf(keyPub.getBitStrength()));
			 System.out.println( "isEncryptionKey: "+ String.valueOf(keyPub.isEncryptionKey()));
			 System.out.println( "isMasterKey: "+ String.valueOf(keyPub.isMasterKey()));
			 System.out.println( "isRevoked: "+ String.valueOf(keyPub.isRevoked()));
			 
			 System.out.println("Plain Text-----------------------------------------------");
				System.out.println(plainText);
			 System.out.println("Encryption Start. Below is the Encrypted Data-------------------------------------");
			 
			 ByteArrayOutputStream out = new ByteArrayOutputStream();
			 InputStream inputStream = new ByteArrayInputStream(plainText.getBytes(Charset.forName("UTF-8")));
			 PGPEncrypt.encrypt(inputStream, out, keyPub, keyPub.getAlgorithm() , true, null);
			 System.out.println(out.toString("UTF-8"));
			
		}catch(Exception e){
			System.out.println(e.getLocalizedMessage());
		}

	}

}
