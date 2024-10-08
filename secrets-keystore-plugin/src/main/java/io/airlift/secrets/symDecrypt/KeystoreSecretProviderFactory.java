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

import com.google.inject.Injector;
import com.google.inject.Scopes;
import io.airlift.bootstrap.Bootstrap;
import io.airlift.spi.secrets.SecretProvider;
import io.airlift.spi.secrets.SecretProviderFactory;

import java.util.Map;

import static io.airlift.configuration.ConfigBinder.configBinder;

public class KeystoreSecretProviderFactory
        implements SecretProviderFactory
{
    @Override
    public String getName()
    {
        return "symDecrypt";
    }

    @Override
    public SecretProvider createSecretProvider(Map<String, String> config)
    {
        Bootstrap app = new Bootstrap(
                binder -> {
                    configBinder(binder).bindConfig(SymDecryptSecretProviderConfig.class);
                    binder.bind(SecretProvider.class).to(SymDecryptSecretProvider.class).in(Scopes.SINGLETON);
                });

        Injector injector = app
                .doNotInitializeLogging()
                .setRequiredConfigurationProperties(config)
                .initialize();

        return injector.getInstance(SecretProvider.class);
    }
}
