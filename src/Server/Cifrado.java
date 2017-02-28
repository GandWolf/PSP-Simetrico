package Server;

import javax.crypto.*;
import javax.crypto.spec.DESedeKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.util.Arrays.copyOf;

/**
 * Created by Gand on 28/01/17.
 */
public class Cifrado {
        private String frase;
        private String clave;
        private SecretKey pass;
        Cipher cifrar;

        public Cifrado(){
//            pass=generaPass();
//            initCipher();
        }
        //--------------------------------------------------------------------------
        public void setFrase(String fr){
            frase=fr;
        }
        //------------------------------------------------------------------------
        public void initCipher(){
            try {
                cifrar = Cipher.getInstance("DESede");
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(Cifrado.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NoSuchPaddingException ex) {
                Logger.getLogger(Cifrado.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        //--------------------------------------------------------------------------
        public String Codifica(String frase,String clave){
            this.frase = frase;
            this.clave = clave;
            pass = generaPass();
            initCipher();

            byte [] bfrase, ebfrase=null;
            String frase_enc="";
            try {
                String frasecod="";
                cifrar.init(Cipher.ENCRYPT_MODE, pass);
                bfrase=frase.getBytes("UTF8");
                ebfrase=cifrar.doFinal(bfrase);


            } catch (InvalidKeyException ex) {
                Logger.getLogger(Cifrado.class.getName()).log(Level.SEVERE, null, ex);
            } catch (UnsupportedEncodingException ex) {
                Logger.getLogger(Cifrado.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IllegalBlockSizeException ex) {
                Logger.getLogger(Cifrado.class.getName()).log(Level.SEVERE, null, ex);
            } catch (BadPaddingException ex) {
                Logger.getLogger(Cifrado.class.getName()).log(Level.SEVERE, null, ex);
            }
            Base64.Encoder encoder = Base64.getEncoder();
            frase_enc = encoder.encodeToString(ebfrase);
            return frase_enc;
        }
        //--------------------------------------------------------------------------
        public String Decodifica(String frase, String clave){
            this.frase = frase;
            this.clave = clave;
            pass=generaPass();
            initCipher();

            byte [] frase1, frase2=null;
            Base64.Decoder decoder = Base64.getDecoder();
            frase1 = decoder.decode(frase);
            try {
                cifrar.init(Cipher.DECRYPT_MODE, pass);
                frase2=cifrar.doFinal(frase1);
            } catch (InvalidKeyException ex) {
                Logger.getLogger(Cifrado.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IllegalBlockSizeException ex) {
                Logger.getLogger(Cifrado.class.getName()).log(Level.SEVERE, null, ex);
            } catch (BadPaddingException ex) {
                Logger.getLogger(Cifrado.class.getName()).log(Level.SEVERE, null, ex);
            }
            Base64.Encoder encoder = Base64.getEncoder();
            String fraseb64 = encoder.encodeToString(frase2);
            return new String(decoder.decode(fraseb64));

        }
        //-------------------------------------------------------------------------
        public SecretKey generaPass(){
            KeySpec sc;
            SecretKeyFactory skf;
            SecretKey sk=null;
            byte [] clave1;
            byte [] clave2;
            try {
                clave1 = clave.getBytes("UTF8");
                clave2 = copyOf(clave1, 24);
                sc = new DESedeKeySpec(clave2);
                skf = SecretKeyFactory.getInstance("DESede");
                sk = skf.generateSecret(sc);
            } catch (UnsupportedEncodingException ex) {
                Logger.getLogger(Cifrado.class.getName()).log(Level.SEVERE, null, ex);
            } catch (InvalidKeyException ex) {
                Logger.getLogger(Cifrado.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(Cifrado.class.getName()).log(Level.SEVERE, null, ex);
            } catch (InvalidKeySpecException ex) {
                Logger.getLogger(Cifrado.class.getName()).log(Level.SEVERE, null, ex);
            }

            return sk;
        }
}
