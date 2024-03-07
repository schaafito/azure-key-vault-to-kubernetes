/*
Copyright Sparebanken Vest

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package client

import (
	"net/http"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azcertificates"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
	"github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/azure"
)

// Adds options to the Azure KeyVault Service to support running on private or
//	soverign cloud environments where api versions and support lag behind public
//	cloud options

// Service Options has configurations for the Azure KeyVault service
type ServiceOptions struct {
	ApiVersion                           string
	DisableChallengeResourceVerification bool
}

// ApiVersionPolicy is wrapper to force the KeyVault client objects to allow changing the
//	ApiVersion. The base client implementations do not allow this but for AzureStack environments
//	we need the ability to set the API to a compatible version. The default implementation will
//	use the pre-configured api-version
//
// Use with caution
type ApiVersionPolicy struct {
	apiVersion string
}

// NewServiceWithApiVersion creates a new AzureKeyVaultService that supports changing the api-version
func NewServiceWithOptions(creds azure.LegacyTokenCredential, keyVaultDNSSuffix string, options *ServiceOptions) Service {
	if options == nil {
		options = &ServiceOptions{
			ApiVersion: "",
			DisableChallengeResourceVerification: false,
		}
	}
	return &azureKeyVaultService{
		credentials:       creds,
		keyVaultDNSSuffix: keyVaultDNSSuffix,
		serviceOptions:    options,
	}
}

// Do implementation of policy.Policy.Do() to change the api-version for KeyVault client requests
func (p *ApiVersionPolicy) Do(req *policy.Request) (*http.Response, error) {
	if p.apiVersion != "" {
		reqQP := req.Raw().URL.Query()
		reqQP.Set("api-version", p.apiVersion)
		req.Raw().URL.RawQuery = reqQP.Encode()
	}
	return req.Next()
}

func (service *azureKeyVaultService) keysClientOptions() *azkeys.ClientOptions {
	return &azkeys.ClientOptions{
		ClientOptions: service.clientOptions(),
		DisableChallengeResourceVerification: service.serviceOptions.DisableChallengeResourceVerification,
	}
}

func (service *azureKeyVaultService) secretsClientOptions() *azsecrets.ClientOptions {
	return &azsecrets.ClientOptions{
		ClientOptions: service.clientOptions(),
		DisableChallengeResourceVerification: service.serviceOptions.DisableChallengeResourceVerification,
	}
}

func (service *azureKeyVaultService) certificatesClientOptions() *azcertificates.ClientOptions {
	return &azcertificates.ClientOptions{
		ClientOptions: service.clientOptions(),
		DisableChallengeResourceVerification: service.serviceOptions.DisableChallengeResourceVerification,
	}
}

// clientOptions returns a policy.ClientOptions based on the azureKeyVaultService configuration
func (service *azureKeyVaultService) clientOptions() policy.ClientOptions {
	if service.serviceOptions.ApiVersion == "" {
		return policy.ClientOptions{}
	}
	return policy.ClientOptions{
		PerCallPolicies: []policy.Policy{
			&ApiVersionPolicy{
				apiVersion: service.serviceOptions.ApiVersion,
			},
		},
	}
}
