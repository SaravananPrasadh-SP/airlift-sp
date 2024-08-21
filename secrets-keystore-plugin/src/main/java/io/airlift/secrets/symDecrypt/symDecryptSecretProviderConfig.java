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

import io.airlift.configuration.Config;

public class SymDecryptSecretProviderConfig
{
    @Config("algorithm")
    public SymDecryptSecretProviderConfig setAlgorithm(String algorithm)
    {
        this.algorithm = algorithm;
        return this;
    }

    public String getAlgorithm()
    {
        return this.algorithm;
    }

    @Config("secret-key-algorithm")
    public SymDecryptSecretProviderConfig setSecretKeyAlgorithm(String secretKeyAlgorithm)
    {
        this.secretKeyAlgorithm = secretKeyAlgorithm;
        return this;
    }

    public String getSecretKeyAlgorithm()
    {
        return this.secretKeyAlgorithm;
    }

    @Config("key-length")
    public SymDecryptSecretProviderConfig setKeyLength(int keyLength)
    {
        this.keyLength = keyLength;
        return this;
    }

    public int getKeyLength()
    {
        return this.keyLength;
    }

    @Config("iteration-count")
    public SymDecryptSecretProviderConfig setIterationCount(int iterationCount)
    {
        this.iterationCount = iterationCount;
        return this;
    }

    public int getIterationCount()
    {
        return this.iterationCount;
    }
}
