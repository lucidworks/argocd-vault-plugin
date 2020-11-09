package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	yaml2 "github.com/ghodss/yaml"
	api "github.com/hashicorp/vault/api"
	"github.com/spf13/cobra"
	yaml "gopkg.in/yaml.v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NewGenerateCommand Initializes the generate command
func NewGenerateCommand() *cobra.Command {
	var command = &cobra.Command{
		Use:   "generate <path>",
		Short: "Generate manifests from templates with Vault values",
		RunE: func(cmd *cobra.Command, args []string) error {

			// Read YAML
			path := args[0]
			files := listYamlFiles(path)
			if len(files) < 1 {
				return fmt.Errorf("No YAML files were found in %s", path)
			}

			// TODO: dispatch on `kind` of each manifest, to find/replace from proper path in Vault
			// TODO: read manifests into well-defined structs
			// secrets := readFilesAsSecrets(files)
			// generated := generateSecrets(&secrets)
			// results := secretsAsYaml(generated)
			// fmt.Print(results)
			return nil
		},
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return errors.New("<path> argument is required to generate manifests")
			}
			return nil
		},
	}

	return command
}

func listYamlFiles(root string) []string {
	var files []string

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if filepath.Ext(path) == ".yaml" {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		panic(err)
	}

	return files
}

func readFilesAsSecrets(paths []string) []map[string]interface{} {
	var result []map[string]interface{}

	for _, path := range paths {
		result = append(result, readFileAsSecret(path))
	}

	return result
}

func readFileAsSecret(path string) map[string]interface{} {
	dat, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}

	return secretFromYaml(dat)
}

func secretFromYaml(data []byte) map[string]interface{} {
	var value map[string]interface{}

	err := yaml.Unmarshal(data, &value)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	return value
}

func generateSecrets(templates *[]map[string]interface{}) *[]corev1.Secret {
	var results []corev1.Secret

	results = []corev1.Secret{}

	for _, secretTemplate := range *templates {
		results = append(results, *generateSecret(secretTemplate))
	}

	return &results
}

func generateSecret(template map[string]interface{}) *corev1.Secret {
	annotations := map[string]string{}
	annotationsInterface := template["metadata"].(map[interface{}]interface{})["annotations"].(map[interface{}]interface{})

	for key, value := range annotationsInterface {
		strKey := fmt.Sprintf("%v", key)
		strValue := fmt.Sprintf("%v", value)

		annotations[strKey] = strValue
	}

	vaultData := readFromVault("g")

	data := map[string][]byte{}

	r := strings.NewReplacer("<", "", ">", "")

	dataInterface := template["data"].(map[interface{}]interface{})
	for key, val := range dataInterface {
		strKey := fmt.Sprintf("%v", key)
		strVal := r.Replace(val.(string))

		data[strKey] = []byte(vaultData[strVal].(string))
	}

	name := template["metadata"].(map[interface{}]interface{})["name"].(string)

	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Annotations: annotations,
		},
		Data: data,
	}
}

func secretsAsYaml(secrets *[]corev1.Secret) string {
	var result string

	result = ""

	for _, s := range *secrets {
		jsonSecret, err := json.Marshal(&s)
		if err != nil {
			panic(err)
		}

		yamlSecret, _ := yaml2.JSONToYAML(jsonSecret)

		result = fmt.Sprintf("%s---\n%s\n", result, string(yamlSecret))
	}

	return result
}

func readFromVault(path string) map[string]interface{} {
	var httpClient = &http.Client{
		Timeout: 10 * time.Second,
	}

	client, err := api.NewClient(&api.Config{Address: "", HttpClient: httpClient})
	if err != nil {
		panic(err)
	}

	client.SetToken("")
	data, err := client.Logical().Read(path)
	if err != nil {
		panic(err)
	}

	return data.Data
}
