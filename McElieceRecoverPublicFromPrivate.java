package com.github.jameskpolk;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.mceliece.*;
import org.bouncycastle.pqc.jcajce.provider.mceliece.BCMcElieceCCA2PrivateKey;
import org.bouncycastle.pqc.jcajce.provider.mceliece.BCMcElieceCCA2PublicKey;
import org.bouncycastle.pqc.math.linearalgebra.*;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class McElieceRecoverPublicFromPrivate {
    private static final SecureRandom RAND = new SecureRandom();

    public static AsymmetricCipherKeyPair generateKeyPair() {
        McElieceCCA2KeyPairGenerator kpg = new McElieceCCA2KeyPairGenerator();
        McElieceCCA2Parameters params = new McElieceCCA2Parameters();
        McElieceCCA2KeyGenerationParameters genParam = new McElieceCCA2KeyGenerationParameters(RAND, params);
        kpg.init(genParam);
        return kpg.generateKeyPair();
    }

    public static McElieceCCA2PublicKeyParameters recoverPubFromPriv(McElieceCCA2PrivateKeyParameters priv) {
        GF2mField field = priv.getField();
        PolynomialGF2mSmallM gp = priv.getGoppaPoly();
        GF2Matrix h = GoppaCode.createCanonicalCheckMatrix(field, gp);
        Permutation p = priv.getP();
        GF2Matrix hp = (GF2Matrix) h.rightMultiply(p);
        GF2Matrix sInv = hp.getLeftSubMatrix();
        GF2Matrix s = (GF2Matrix) sInv.computeInverse();
        GF2Matrix shp = (GF2Matrix)s.rightMultiply(hp);
        GF2Matrix m = shp.getRightSubMatrix();

        GoppaCode.MaMaPe mmp = new GoppaCode.MaMaPe(sInv, m, p);
        GF2Matrix shortH = mmp.getSecondMatrix();
        GF2Matrix shortG = (GF2Matrix) shortH.computeTranspose();
        // generate public key
        return new McElieceCCA2PublicKeyParameters(
                priv.getN(), gp.getDegree(), shortG,
                priv.getDigest());
    }

    public static void main(String[] args) throws Exception{

        // generate a McEliece key pair

        AsymmetricCipherKeyPair bcKeyPair = generateKeyPair();
        McElieceCCA2PrivateKeyParameters bcPriv = (McElieceCCA2PrivateKeyParameters) bcKeyPair.getPrivate();
        BCMcElieceCCA2PrivateKey priv = new BCMcElieceCCA2PrivateKey(bcPriv);

        // get the first public key

        McElieceCCA2PublicKeyParameters bcPub1 = (McElieceCCA2PublicKeyParameters) bcKeyPair.getPublic();
        BCMcElieceCCA2PublicKey pub1 = new BCMcElieceCCA2PublicKey(bcPub1);

        // Now generate a second public key for the private key

        McElieceCCA2PublicKeyParameters bcPub2 = recoverPubFromPriv(bcPriv);
        BCMcElieceCCA2PublicKey pub2 = new BCMcElieceCCA2PublicKey(bcPub2);

        // print some info about sizes

        System.out.printf("Size of encrypted messages in bits(bytes): %d(%d)\n",
                priv.getEncoded().length, priv.getEncoded().length / 8);
        System.out.printf("private key length: %d\n", bcPriv.getK());
        System.out.printf("public key1 length: %d\n", pub1.getEncoded().length);
        System.out.printf("public key2 length: %d\n", pub2.getEncoded().length);

        // now encrypt different messages with each public key.

        String message1 = "Deposits should be made to account # 3.1415929";
        String message2 = "Deposits should be made to account # 2.71828";

        ParametersWithRandom params1 = new ParametersWithRandom(bcPub1, RAND);
        ParametersWithRandom params2 = new ParametersWithRandom(bcPub2, RAND);

        McElieceFujisakiCipher mcElieceFujisakiDigestCipher1 = new McElieceFujisakiCipher();
        McElieceFujisakiCipher mcElieceFujisakiDigestCipher2 = new McElieceFujisakiCipher();
        mcElieceFujisakiDigestCipher1.init(true, params1);
        mcElieceFujisakiDigestCipher2.init(true, params2);

        byte[] ciphertext1 = mcElieceFujisakiDigestCipher1.messageEncrypt(message1.getBytes(StandardCharsets.UTF_8));
        byte[] ciphertext2 = mcElieceFujisakiDigestCipher2.messageEncrypt(message2.getBytes(StandardCharsets.UTF_8));
        System.out.println("ct1 length:    " + ciphertext1.length + " (" + (ciphertext1.length / (1024 * 1024)) + " mb)");
        System.out.println("ct2 length:    " + ciphertext2.length + " (" + (ciphertext2.length / (1024 * 1024)) + " mb)");

        mcElieceFujisakiDigestCipher1.init(false, bcPriv);
        mcElieceFujisakiDigestCipher2.init(false, bcPriv);

        byte[] decryptedtext1 = mcElieceFujisakiDigestCipher1.messageDecrypt(ciphertext1);
        byte[] decryptedtext2 = mcElieceFujisakiDigestCipher2.messageDecrypt(ciphertext2);

        System.out.printf("Decrypted message 1: %s\n", new String(decryptedtext1, StandardCharsets.UTF_8));
        System.out.printf("Decrypted message 2: %s\n", new String(decryptedtext2, StandardCharsets.UTF_8));

    }
}
