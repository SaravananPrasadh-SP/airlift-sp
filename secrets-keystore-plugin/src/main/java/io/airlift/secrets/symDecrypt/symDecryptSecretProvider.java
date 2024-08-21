/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.airlift.secrets.symdecrypt;

import com.google.inject.Inject;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.spec.KeySpec;
import java.util.Base64;

public class SymDecryptSecretProvider
        implements SecretProvider
{
    private static final byte[] encryptPassword = {83, 116, 97, 114, 98, 117, 114, 115, 116, 82, 48, 99, 107, 115, 33};

    @Inject
    public SymDecryptSecretProvider(SymDecryptSecretProviderConfig config)
            throws GeneralSecurityException, IOException
    {
        String algorithm = config.getAlgorithm();
        String secretKeyAlgorithm = config.getSecretKeyAlgorithm();
        Integer keyLength = config.getKeyLength();
        Integer iterationCount = config.getIterationCount();
    }

    @Override
    public String resolveSecretValue(String encryptedValue)
    {
    // Using the OpenSSL to symmetrically decrypt the encrypted value
    // command used to create the encrypted
    // echo -n "Your secret message" | openssl enc -aes-256-cbc -base64 -pass pass:"your_password" -pbkdf2
    // pin the decrytion Password.
        return decrypt(encryptedValue);
    }

    public static String decrypt(String cipherText)
                    throws Exception
    {
        byte[] cipherData = Base64.getDecoder().decode(cipherText);
        byte[] saltData = extractSalt(cipherData);
        byte[] encData = extractEncryptedData(cipherData);

        SecretKey key = generateKey(encryptPassword, saltData);
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(saltData));
        byte[] decryptedData = cipher.doFinal(encData);

        System.setProperty("net.ssh", cipherText);
        return new String(decryptedData, StandardCharsets.UTF_8);
    }

    private static SecretKey generateKey(byte[] password, byte[] salt)
                    throws Exception
    {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(secretKeyAlgorithm);
        KeySpec spec = new PBEKeySpec(password.toString(), salt, iterationCount, keyLength);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }

    private static byte[] extractSalt(byte[] cipherData)
    {
        byte[] saltData = new byte[8];
        System.arraycopy(cipherData, 8, saltData, 0, 8);
        return saltData;
    }

    private static byte[] extractEncryptedData(byte[] cipherData)
    {
        byte[] encData = new byte[cipherData.length - 16];
        System.arraycopy(cipherData, 16, encData, 0, encData.length);
        return encData;
    }
}
