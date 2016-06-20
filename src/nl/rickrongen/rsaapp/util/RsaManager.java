package nl.rickrongen.rsaapp.util;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by Rick on 20-6-2016.
 */
public class RsaManager {
    private static RsaManager instance;
    public static RsaManager getInstance(){
        return instance == null? (instance = new RsaManager()) : instance;
    }

    private static final Logger LOG = Logger.getLogger(RsaManager.class.getName());

    public RsaManager() {
    }

    public boolean sign(String tosign, String privateKey, String username){
        RSAPrivateKey privkey;
        try {
            privkey = getPrivateKey(privateKey);
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }

        try{
            File file = new File(tosign);
            FileInputStream fin = new FileInputStream(file);
            byte[] data = new byte[(int)file.length()];
            fin.read(data);
            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initSign(privkey);

            signature.update(data);
            byte[] signed = signature.sign();

            String outputfile = tosign.substring(0,tosign.lastIndexOf(".")) + "(Signed by " + username + ")" + tosign.substring(tosign.lastIndexOf('.'));
            File output = new File(outputfile);
            DataOutputStream fout = new DataOutputStream(new FileOutputStream(output));
            fout.writeInt(signed.length);
            fout.write(signed);
            fout.write(data);
            return true;
        } catch (IOException | NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            e.printStackTrace();
            return false;
        }
    }

    public boolean verify(String signedFile, String keyFile)  {
        RSAPublicKey publkey;
        try {
            publkey = getPublicKey(keyFile);

            File sigfile = new File(signedFile);
            DataInputStream din = new DataInputStream(new FileInputStream(sigfile));
            int lenght = din.readInt();
            byte[] filesignature = new byte[lenght];
            din.read(filesignature);
            byte[] file = new byte[(int)sigfile.length()-lenght-4];//get any bytes left
            din.read(file);

            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initVerify(publkey);
            signature.update(file);
            boolean isOk = signature.verify(filesignature);
            if(isOk){
                FileOutputStream fout = new FileOutputStream(signedFile.substring(0,signedFile.lastIndexOf('(')) + " verified" + signedFile.substring(signedFile.lastIndexOf('.')));
                fout.write(file);
            }
            return isOk;
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            e.printStackTrace();
            return false;
        }
    }

    private RSAPrivateKey getPrivateKey(String filename) throws FileNotFoundException, IOException{
        File pubkey = new File(filename);
        if(!pubkey.exists() || pubkey.canRead()){
//            throw new FileNotFoundException();
        }
        DataInputStream in = new DataInputStream(new FileInputStream(pubkey));
        int modSize = in.readInt();
        int privSize = in.readInt();
        byte[] mod = new byte[modSize];
        byte[] priv = new byte[privSize];

        in.read(mod, 0, modSize);
        in.read(priv,0,privSize);

        BigInteger bMod = new BigInteger(mod);
        BigInteger bPriv = new BigInteger(priv);

        KeyFactory fact;
        try {
            fact = KeyFactory.getInstance("RSA");
            return (RSAPrivateKey)fact.generatePrivate(new RSAPrivateKeySpec(bMod,bPriv));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            LOG.log(Level.SEVERE, null, ex);
            return null;
        }
    }

    public RSAPublicKey getPublicKey(String filename) throws FileNotFoundException, IOException{
        File pubkey = new File(filename);
        if(!pubkey.exists() || pubkey.canRead()){
//            throw new FileNotFoundException();
        }
        DataInputStream in = new DataInputStream(new FileInputStream(pubkey));
        int modSize = in.readInt();
        int pubSize = in.readInt();
        byte[] mod = new byte[modSize];
        byte[] pub = new byte[pubSize];

        in.read(mod, 0, modSize);
        in.read(pub,0,pubSize);

        BigInteger bMod = new BigInteger(mod);
        BigInteger bPub = new BigInteger(pub);

        KeyFactory fact;
        try {
            fact = KeyFactory.getInstance("RSA");
            return  (RSAPublicKey)fact.generatePublic(new RSAPublicKeySpec(bMod,bPub));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            LOG.log(Level.SEVERE, null, ex);
            return null;
        }
    }

    public void storekeypair(KeyPair pair, String privateFilePath, String publicFilePath) throws IOException {

        RSAPrivateKey privateKey = (RSAPrivateKey) pair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey) pair.getPublic();

        LOG.info("Storing keys into files");
        try (DataOutputStream privOut = new DataOutputStream(new FileOutputStream(privateFilePath))) {
            byte[] modules = privateKey.getModulus().toByteArray();
            byte[] privateExp = privateKey.getPrivateExponent().toByteArray();
            privOut.writeInt(modules.length);
            privOut.writeInt(privateExp.length);
            privOut.write(modules);
            privOut.write(privateExp);
            privOut.flush();
        }
        try (DataOutputStream pubOut = new DataOutputStream(new FileOutputStream(publicFilePath))) {
            byte[] modules = publicKey.getModulus().toByteArray();
            byte[] publicExp = publicKey.getPublicExponent().toByteArray();
            pubOut.writeInt(modules.length);
            pubOut.writeInt(publicExp.length);
            pubOut.write(modules);
            pubOut.write(publicExp);
            pubOut.flush();
        }
    }

    public KeyPair createKeys(){
        return createKeys(1024);
    }

    public KeyPair createKeys(int bits) {
        LOG.info("Initialising Generator");
        KeyPairGenerator gen;
        try {
            gen = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
        LOG.info("Generating keypair of " + bits + " bits");
        gen.initialize(2048, new SecureRandom());
        LOG.info("Generating keys");
        return gen.generateKeyPair();
    }
}
