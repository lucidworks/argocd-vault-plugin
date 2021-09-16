package backends

import (
	"errors"
	"fmt"
	"regexp"
	"sync"

	"github.com/IBM/go-sdk-core/v5/core"
	ibmsm "github.com/IBM/secrets-manager-go-sdk/secretsmanagerv1"
)

var IBMPath, _ = regexp.Compile(`ibmcloud/(?P<type>.+)/secrets/groups/(?P<groupid>.+)`)

// IBMSecretsManagerClient is an interface for any client to the IBM Secrets Manager
// These are only the methods we need
type IBMSecretsManagerClient interface {
	ListAllSecrets(listAllSecretsOptions *ibmsm.ListAllSecretsOptions) (result *ibmsm.ListSecrets, response *core.DetailedResponse, err error)
	GetSecret(getSecretOptions *ibmsm.GetSecretOptions) (result *ibmsm.GetSecret, response *core.DetailedResponse, err error)
}

// IBMSecretsManager is a struct for working with IBM Secret Manager
type IBMSecretsManager struct {
	Client IBMSecretsManagerClient
}

// NewIBMSecretsManagerBackend initializes a new IBM Secret Manager backend
func NewIBMSecretsManagerBackend(client IBMSecretsManagerClient) *IBMSecretsManager {
	ibmSecretsManager := &IBMSecretsManager{
		Client: client,
	}
	return ibmSecretsManager
}

// Login does nothing since the IBM Secrets Manager client is setup on instantiation
func (i *IBMSecretsManager) Login() error {
	return nil
}

// GetSecrets returns the data for a secret in IBM Secrets Manager
// It only works for `arbitrary` secret types
// func (i *IBMSecretsManager) GetSecrets(path string, version string, annotations map[string]string) (map[string]interface{}, error) {
// 	// IBM SM users pass the path of a secret _group_ which contains a list of secrets
// 	// ex: <path:ibmcloud/arbitrary/secrets/groups/123#username>
// 	// So we query the group to enumerate the secret ids, and retrieve each one to return a complete map of them
// 	matches := IBMPath.FindStringSubmatch(path)
// 	if len(matches) == 0 {
// 		return nil, fmt.Errorf("Path is not in the correct format (ibmcloud/$TYPE/secrets/groups/$GROUP_ID) for IBM Secrets Manager: %s", path)
// 	}
//
// 	// Enumerate the secret names and their ids
// 	groupid := matches[IBMPath.SubexpIndex("groupid")]
// 	result, details, err := i.Client.ListAllSecrets(&ibmsm.ListAllSecretsOptions{
// 		Groups: []string{groupid},
// 	})
//
// 	if err != nil {
// 		return nil, fmt.Errorf("Could not list secrets for secret group %s: %s\n%s", groupid, err, details)
// 	}
//
// 	secrets := make(map[string]interface{})
// 	for _, resource := range result.Resources {
// 		if secret, ok := resource.(*ibmsm.SecretResource); ok {
// 			if *secret.SecretType == matches[IBMPath.SubexpIndex("type")] {
// 				secrets[*secret.Name] = secret.ID
// 			}
// 		}
// 	}
//
// 	var mutex = &sync.Mutex{}
// 	var wg sync.WaitGroup
// 	ch := make(chan error)
//
// 	wg.Add(len(secrets))
//
// 	// Get each secrets value from its ID
// 	for name, id := range secrets {
//
// 		go func(name string, id interface{}, ch chan<- error) {
// 			// `version` is ignored since IBM SM does not support versioning for `arbitrary` secrets
// 			// https://github.com/IBM/argocd-vault-plugin/issues/58#issuecomment-906477921
// 			secretRes, _, err := i.Client.GetSecret(&ibmsm.GetSecretOptions{
// 				SecretType: &matches[IBMPath.SubexpIndex("type")],
// 				ID:         id.(*string),
// 			})
// 			if err != nil {
// 				ch <- fmt.Errorf("Could not retrieve secret %s: %s", *(id.(*string)), err)
// 				wg.Done()
// 				return
// 			}
//
// 			secretResource := secretRes.Resources[0].(*ibmsm.SecretResource)
// 			secretData := secretResource.SecretData.(map[string]interface{})
//
// 			mutex.Lock()
//
// 			secrets[name] = secretData["payload"]
//
// 			mutex.Unlock()
//
// 			if secrets[name] == nil {
// 				ch <- fmt.Errorf("No `payload` key present for secret at path %s: Is this an `arbitrary` type secret?", path)
// 				wg.Done()
// 				return
// 			}
//
// 			wg.Done()
// 		}(name, id, ch)
// 	}
//
// 	go func() {
// 		wg.Wait()
// 		close(ch)
// 	}()
//
// 	for e := range ch {
// 		if e != nil {
// 			return nil, e
// 		}
// 	}
//
// 	// fmt.Println(fmt.Sprintf("Secrets - %v", secrets))
// 	return secrets, nil
// }

func (i *IBMSecretsManager) getSecret(secret *ibmsm.SecretResource, wg *sync.WaitGroup, response chan map[string]interface{}) {
	result := make(map[string]interface{})
	result["name"] = *secret.Name

	secretRes, _, err := i.Client.GetSecret(&ibmsm.GetSecretOptions{
		SecretType: secret.SecretType,
		ID:         secret.ID,
	})
	if err != nil {
		result["err"] = fmt.Sprintf("Could not retrieve secret %s: %s", *secret.ID, err)
		wg.Done()
		return
	}

	secretResource := secretRes.Resources[0].(*ibmsm.SecretResource)
	secretData := secretResource.SecretData.(map[string]interface{})
	if secretData["payload"] == nil {
		result["err"] = fmt.Sprintf("No `payload` key present for secret with id %s: Is this an `arbitrary` type secret?", *secret.ID)
	} else {
		result["data"] = secretData["payload"]
	}

	response <- result

	wg.Done()
}

// GetSecrets returns the data for a secret in IBM Secrets Manager
// It only works for `arbitrary` secret types
/*
real    0m4.566s
user    0m0.082s
sys     0m0.037s
*/
func (i *IBMSecretsManager) GetSecrets(path string, version string, annotations map[string]string) (map[string]interface{}, error) {
	// IBM SM users pass the path of a secret _group_ which contains a list of secrets
	// ex: <path:ibmcloud/arbitrary/secrets/groups/123#username>
	// So we query the group to enumerate the secret ids, and retrieve each one to return a complete map of them
	matches := IBMPath.FindStringSubmatch(path)
	if len(matches) == 0 {
		return nil, fmt.Errorf("Path is not in the correct format (ibmcloud/$TYPE/secrets/groups/$GROUP_ID) for IBM Secrets Manager: %s", path)
	}

	// Enumerate the secret names and their ids
	groupid := matches[IBMPath.SubexpIndex("groupid")]
	result, details, err := i.Client.ListAllSecrets(&ibmsm.ListAllSecretsOptions{
		Groups: []string{groupid},
	})

	if err != nil {
		return nil, fmt.Errorf("Could not list secrets for secret group %s: %s\n%s", groupid, err, details)
	}

	secretResult := make(chan map[string]interface{})
	secrets := make(map[string]interface{})

	var wg sync.WaitGroup

	for _, resource := range result.Resources {
		if secret, ok := resource.(*ibmsm.SecretResource); ok {
			if *secret.SecretType == matches[IBMPath.SubexpIndex("type")] {
				// `version` is ignored since IBM SM does not support versioning for `arbitrary` secrets
				// https://github.com/IBM/argocd-vault-plugin/issues/58#issuecomment-906477921
				wg.Add(1)
				go i.getSecret(secret, &wg, secretResult)
			}
		}
	}

	go func() {
		wg.Wait()
		close(secretResult)
	}()

	for result := range secretResult {
		if result["err"] != nil {
			return nil, errors.New(result["err"].(string))
		}
		secrets[result["name"].(string)] = result["data"]
	}

	return secrets, nil
}
