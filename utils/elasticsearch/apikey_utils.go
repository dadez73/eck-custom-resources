package elasticsearch

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"eck-custom-resources/api/es.eck/v1alpha1"
	"eck-custom-resources/utils"

	"github.com/elastic/go-elasticsearch/v8"
	k8sv1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

//func GetAPIKeyfromSecret(cli client.Client, ctx context.Context, esClient *elasticsearch.Client, apikey v1alpha1.ElasticsearchApikey, req ctrl.Request) (string, error) {

func DeleteApikey(cli client.Client, ctx context.Context, esClient *elasticsearch.Client, apikey v1alpha1.ElasticsearchApikey, req ctrl.Request) (ctrl.Result, error) {
	data, err := GetAPIKeySecret(cli, ctx, req.Namespace, req.Name)
	if err != nil {
		return utils.GetRequeueResult(), fmt.Errorf("error calling GetAPIKeySecret: %s", apikey.Spec.Body)
	}
	apikeyId := string(data["id"])

	res, err := esClient.Security.InvalidateAPIKey(strings.NewReader(fmt.Sprintf(`{"ids": "%s"}`, apikeyId)),
		esClient.Security.InvalidateAPIKey.WithContext(context.Background()))

	defer res.Body.Close()

	if err != nil || res.IsError() {
		return utils.GetRequeueResult(), fmt.Errorf("error response from InvalidateAPIKey: %s", apikeyId)
	}

	if err := DeleteApikeySecret(cli, ctx, req.Namespace, req.Name); err != nil {
		return utils.GetRequeueResult(), err
	}

	return ctrl.Result{}, nil
}

func CreateApikey(cli client.Client, ctx context.Context, esClient *elasticsearch.Client, apikey v1alpha1.ElasticsearchApikey, req ctrl.Request) (ctrl.Result, error) {

	secretData, _ := GetAPIKeySecret(cli, ctx, req.Namespace, req.Name)

	apikeyId := string(secretData["id"])

	secretExists := (secretData != nil)

	getRes, err := esClient.Security.GetAPIKey(
		esClient.Security.GetAPIKey.WithName(req.Name),
		esClient.Security.GetAPIKey.WithActiveOnly(true),
	)

	if err != nil {
		return utils.GetRequeueResult(), fmt.Errorf("error checking existing API key: %w", err)
	}
	defer getRes.Body.Close()

	if getRes.IsError() {
		return utils.GetRequeueResult(), fmt.Errorf("error response from GetAPIKey: %s", getRes.String())
	}

	var getResp struct {
		APIKeys []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"api_keys"`
	}

	if err := json.NewDecoder(getRes.Body).Decode(&getResp); err != nil {
		return utils.GetRequeueResult(), fmt.Errorf("error decoding GetAPIKey response: %w", err)
	}

	// Step 2: Check if some keys already exists
	keyExists := (len(getResp.APIKeys) > 0)

	switch {
	case secretExists && keyExists:
		// Ensure Secret content matches known key info (id and encodedKey may be absent on later reads)
		// We only ensure id is correct; encodedKey is only known at creation time.
		if containsID(getResp.APIKeys, apikeyId) {
			// If this is an UPDATE event: update only the "body"

			apiBody, _ := removeNameField(apikey.Spec.Body)

			if _, err := esClient.Security.UpdateAPIKey(
				apikeyId,
				esClient.Security.UpdateAPIKey.WithBody(strings.NewReader(apiBody)),
				esClient.Security.UpdateAPIKey.WithContext(context.Background()),
			); err != nil {
				return utils.GetRequeueResult(), fmt.Errorf("error updating APIKey response: %w", err)
			}
		}
	default:
		// (!secretExists && !keyExists) or (secretExists && !keyExists) or (!secretExists && keyExists:)
		// Neither exists → create key, then create Secret
		// Key exists but Secret missing → create Secret from existing key

		response, err := esClient.Security.CreateAPIKey(
			strings.NewReader(apikey.Spec.Body),
		)
		if err != nil {
			return utils.GetRequeueResult(), GetClientErrorOrResponseError(err, response)
		}
		defer response.Body.Close()

		if response.IsError() {
			return utils.GetRequeueResult(), fmt.Errorf("error creating API key: %s", response.String())
		}
		body, err := io.ReadAll(response.Body)
		if err != nil {
			return utils.GetRequeueResult(), err
		}

		var responseMap map[string]interface{}
		err = json.Unmarshal([]byte(body), &responseMap)
		if err != nil {
			return utils.GetRequeueResult(), err
		}

		apikeyId, ok := responseMap["id"].(string)
		if !ok {
			fmt.Println("ApikeyId's value conversion failed")
		}
		apikeyName, ok := responseMap["name"].(string)
		if !ok {
			fmt.Println("ApikeyName's value conversion failed")
		}
		apikeyEncoded, ok := responseMap["encoded"].(string)
		if !ok {
			fmt.Println("ApikeyEncoded's value conversion failed")
		}
		data := map[string][]byte{
			"id":     []byte(apikeyId),
			"name":   []byte(apikeyName),
			"apikey": []byte(apikeyEncoded),
		}

		if err := CreateApikeySecret(cli, ctx, req.Namespace, req.Name, data); err != nil {
			return utils.GetRequeueResult(), err
		}
		apikey.Status.APIKeyID = apikeyId
		if err := cli.Status().Update(ctx, &apikey); err != nil {
			return utils.GetRequeueResult(), fmt.Errorf("error updating API key status: %s", response.String())
		}
	}

	return ctrl.Result{}, nil
}

func GetAPIKeySecret(cli client.Client, ctx context.Context, namespace string, secretName string) (map[string][]byte, error) {
	key := client.ObjectKey{Namespace: namespace, Name: secretName}
	var sec k8sv1.Secret
	if err := cli.Get(ctx, key, &sec); err != nil {
		return nil, err
	}
	return sec.Data, nil
}

func CreateApikeySecret(cli client.Client, ctx context.Context, namespace string, secretName string, data map[string][]byte) error {
	key := client.ObjectKey{Namespace: namespace, Name: secretName}
	var sec k8sv1.Secret

	if err := cli.Get(ctx, key, &sec); err != nil {
		if apierrors.IsNotFound(err) {
			// Create
			sec = k8sv1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespace,
					Name:      secretName,
				},
				Type: k8sv1.SecretTypeOpaque,
				Data: data,
			}
			return cli.Create(ctx, &sec)
		}
		return err
	}

	// Update with Patch to avoid resourceVersion conflicts
	patch := client.MergeFrom(sec.DeepCopy())
	sec.Type = k8sv1.SecretTypeOpaque
	if sec.Data == nil {
		sec.Data = map[string][]byte{}
	}
	for k, v := range data {
		sec.Data[k] = v
	}
	return cli.Patch(ctx, &sec, patch)
}

//	newSecret := &k8sv1.Secret{
//		ObjectMeta: metav1.ObjectMeta{
//			Namespace: namespace,
//			Name:      secretName,
//		},
//		Data: data,
//		Type: k8sv1.SecretTypeOpaque,
//	}
//	cli.Update(ctx, newSecret)
//	if err := cli.Create(ctx, newSecret); err != nil {
//		return err
//	}
//	return nil
//}

func DeleteApikeySecret(cli client.Client, ctx context.Context, namespace string, secretName string) error {
	secret := &k8sv1.Secret{}

	if err := cli.Get(ctx, client.ObjectKey{Namespace: namespace, Name: secretName}, secret); err != nil {
		return err
	}

	if err := cli.Delete(ctx, secret); err != nil {
		return err
	}
	return nil
}

func containsID(apiKeys []struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}, id string) bool {
	for _, k := range apiKeys {
		if k.ID == id {
			return true
		}
	}
	return false
}
func removeNameField(input string) (string, error) {
	var data map[string]interface{}

	// Unmarshal JSON string into a map
	if err := json.Unmarshal([]byte(input), &data); err != nil {
		return "", err
	}

	// Remove "name" field
	delete(data, "name")

	// Marshal back to JSON string
	output, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "", err
	}

	return string(output), nil
}
