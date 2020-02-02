package com.softwareag.pgp;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.Iterator;

public class TestDecryption {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		String path = "C:\\Users\\sravs\\Desktop\\PGP\\newPrivate.asc";
		String pasw = "14a2e87697b444688d2b1b6be8a7d12760615ec06d3a471fa37868ae647ca5ea";
		
		PGPSecretKeyRingCollection ringSecret = null;
		try{
			ringSecret = PGPKeyReader.readSecretKeyRing(path);
			System.out.println(ringSecret.size());
			if(pasw != null){
				main: for (Iterator<?> i = ringSecret.getKeyRings(); i.hasNext();) {
		            PGPSecretKeyRing ring = (PGPSecretKeyRing) i.next();
		            for (Iterator<?> j = ring.getSecretKeys(); j.hasNext();) {
		                PGPSecretKey next = (PGPSecretKey) j.next();
		                try {
		                    //PGPPrivateKey key = next.extractPrivateKey("pgpkey".toCharArray(), PGPInit.PROVIDER);
		                	//JcePBESecretKeyDecryptorBuilder jpkdb = new JcePBESecretKeyDecryptorBuilder().setProvider( new BouncyCastleProvider() ).build("pgpkey".toCharArray());
		                	 
		                	//JcePBESecretKeyDecryptorBuilder jpskdb = new JcePBESecretKeyDecryptorBuilder().setProvider( new BouncyCastleProvider() ).build( "pgpkey".toCharArray() );
		                	int algorithm = next.getKeyEncryptionAlgorithm();
		                	PGPPublicKey ppk = next.getPublicKey();
		                	System.out.println(ppk.getAlgorithm());
		                	System.out.println(algorithm);
		                   PGPPrivateKey key = next.extractPrivateKey(
	               new JcePBESecretKeyDecryptorBuilder().setProvider( new BouncyCastleProvider() ).build( pasw.toCharArray() ) );
		                    
		                    
		                    //PGPPrivateKey key = next.extractPrivateKey(new PBESecretKeyDecryptor("pgpkey".toCharArray()),);
		            	                    
		            	     System.out.println(key);
		                    if (key != null) {
		                        System.out.println("privateKey: "+ key);
		                        System.out.println("keyId: "+ String.valueOf(key.getKeyID()));
		                        //System.out.println( "algorithm: "+ key.g
		                        System.out.println( "algorithm: "+ ppk.getAlgorithm());
		                        //System.out.println( "format: "+ key.getKey().getFormat());
		                        System.out.println( "isSigningKey: "+ String.valueOf(next.isSigningKey()));
		                        System.out.println( "isMasterKey "+ String.valueOf(next.isMasterKey()));
		                        break main;
		                    }
		                } catch (Exception e) {
		                	System.out.println(e.getMessage());
		                }
		            }
		        }
			}
			
			System.out.println("Decryption Start. Below is the Decrypted Data-----------------------------------------");
			InputStream cipherTextStream = new FileInputStream(new File("C:\\Users\\sravs\\Desktop\\PGP\\encryptedString.txt"));
			
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			char[] password = pasw.toCharArray();
			PGPDecrypt.decrypt(cipherTextStream, out, ringSecret, password);
			System.out.println(out.toString());
			
		}catch(Exception e){
			System.out.println(e.getLocalizedMessage());
		}

	}

}
