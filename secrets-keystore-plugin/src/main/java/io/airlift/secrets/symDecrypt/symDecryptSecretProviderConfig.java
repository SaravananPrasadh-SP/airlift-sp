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
package io.airlift.secrets.symDecrypt;

import io.airlift.configuration.Config;
import io.airlift.configuration.ConfigSecuritySensitive;
import io.airlift.configuration.validation.FileExists;
import jakarta.validation.constraints.NotNull;

public class symDecryptSecretProviderConfig
{


    @Config("algorithm")
    public symDecryptSecretProviderConfig setAlgorithm(String algorithm)
    {
        this.algorithm = algorithm;
        return this;
    }
    public String getAlgorithm()
    {
        return algorithm;
    }

    @Config("secret-key-algorithm")
    public symDecryptSecretProviderConfig setSecretKeyAlgorithm(String secretKeyAlgorithm)
    {
        this.secretKeyAlgorithm = secretKeyAlgorithm;
        return this;
    }
    public String getSecretKeyAlgorithm()
    {
        return secretKeyAlgorithm;
    }
    
    @Config("key-length")
    public symDecryptSecretProviderConfig setKeyLength(int keyLength)
    {
        this.keyLength = keyLength;
        return this;
    }
    public int getKeyLength()
    {
        return keyLength;
    }

    @Config("iteration-count")
    public symDecryptSecretProviderConfig setIterationCount(int iterationCount)
    {
        this.iterationCount = iterationCount;
        return this;
    }
    public int getIterationCount()
    {
        return iterationCount;
    }
    
}