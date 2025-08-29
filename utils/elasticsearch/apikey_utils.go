package elasticsearch

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"

	"eck-custom-resources/api/es.eck/v1alpha1"
	"eck-custom-resources/utils"

	"github.com/elastic/go-elasticsearch/v8"
	k8sv1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

type APIKey struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
type GetAPIKeysResponse struct {
	APIKeys []APIKey `json:"api_keys"`
}

// Accepts: -1, 0, or <number>[nanos|micros|ms|s|m|h|d]
// <number> may be an integer or decimal (e.g., 1.5h).
var esDurationRe = regexp.MustCompile(`^(?i)(?:-1|0|(?:\d+(?:\.\d+)?)(?:nanos|micros|ms|s|m|h|d))$`)

func validateExpiration(exp string) (string, error) {
	e := strings.TrimSpace(exp)
	e = strings.ToLower(e) // normalize units
	if esDurationRe.MatchString(e) {
		return e, nil
	}
	return "", fmt.Errorf(
		"invalid expiration %q: must be -1, 0, or <number>[nanos|micros|ms|s|m|h|d] (e.g., 30m, 12h, 1.5h)",
		exp,
	)
}

//func GetAPIKeyfromSecret(cli client.Client, ctx context.Context, esClient *elasticsearch.Client, apikey v1alpha1.ElasticsearchApikey, req ctrl.Request) (string, error) {

func DeleteApikey(cli client.Client, ctx context.Context, esClient *elasticsearch.Client, apikey v1alpha1.ElasticsearchApikey, req ctrl.Request) (ctrl.Result, error) {
	apikeyID, err := GetAPIKeyID(cli, ctx, req, apikey)
	if err != nil {
		return utils.GetRequeueResult(), err
	}

	res, err := esClient.Security.InvalidateAPIKey(strings.NewReader(fmt.Sprintf(`{"ids": "%s"}`, apikeyID)),
		esClient.Security.InvalidateAPIKey.WithContext(context.Background()))

	defer res.Body.Close()

	if err != nil || res.IsError() {
		return utils.GetRequeueResult(), fmt.Errorf("error response from InvalidateAPIKey: %s", apikeyID)
	}

	if err := DeleteApikeySecret(cli, ctx, req.Namespace, req.Name); err != nil {
		return utils.GetRequeueResult(), err
	}

	return ctrl.Result{}, nil
}
func UpdateApikey(cli client.Client, ctx context.Context, esClient *elasticsearch.Client, apikey v1alpha1.ElasticsearchApikey, req ctrl.Request) (ctrl.Result, error) {
	// Ensure Secret content matches known key info (id and encodedKey may be absent on later reads)
	apikeyID, err := GetAPIKeyID(cli, ctx, req, apikey)
	if err != nil {
		return utils.GetRequeueResult(), err
	}
	// If this is an UPDATE event: update only the "body"

	apiBody, _ := removeField(apikey.Spec.Body, "name")

	if _, err := esClient.Security.UpdateAPIKey(
		apikeyID,
		esClient.Security.UpdateAPIKey.WithBody(strings.NewReader(apiBody)),
		esClient.Security.UpdateAPIKey.WithContext(context.Background()),
	); err != nil {
		return utils.GetRequeueResult(), fmt.Errorf("error updating APIKey response: %w", err)
	}

	return ctrl.Result{}, nil
}
func UpdateExpirationApikey(cli client.Client, ctx context.Context, esClient *elasticsearch.Client, apikey APIKey, expiration string) (ctrl.Result, error) {

	// Build body: only expiration is being updated
	normalizedExp, err := validateExpiration(expiration)
	if err != nil {
		return utils.GetRequeueResult(), err
	}
	payload := map[string]any{"expiration": normalizedExp}
	expirationBody, err := json.Marshal(payload)
	if err != nil {
		return utils.GetRequeueResult(), fmt.Errorf("encode update body: %w", err)
	}
	// Call Update API key (must be authenticated as the owner user; NOT with an API key) :contentReference[oaicite:2]{index=2}
	res, err := esClient.Security.UpdateAPIKey(
		apikey.ID,
		esClient.Security.UpdateAPIKey.WithBody(bytes.NewReader(expirationBody)),
		esClient.Security.UpdateAPIKey.WithContext(ctx),
	)
	if err != nil {
		return utils.GetRequeueResult(), fmt.Errorf("update API key %q Expiration call failed: %w", apikey.ID, err)
	}
	defer res.Body.Close()

	return ctrl.Result{}, nil
}
func GetApiKeyWithID(cli client.Client, ctx context.Context, esClient *elasticsearch.Client, apiKeyID string) (APIKey, error) {
	getRes, err := esClient.Security.GetAPIKey(
		esClient.Security.GetAPIKey.WithID(apiKeyID),
		esClient.Security.GetAPIKey.WithActiveOnly(true),
	)

	if err != nil || getRes.IsError() {
		return APIKey{}, err
	}
	defer getRes.Body.Close()
	var getResp GetAPIKeysResponse

	if err := json.NewDecoder(getRes.Body).Decode(&getResp); err != nil {
		return APIKey{}, err
	}
	return getResp.APIKeys[0], err
}
func GetApiKeyWithName(cli client.Client, ctx context.Context, esClient *elasticsearch.Client, apiKeyName string) []APIKey {
	getRes, err := esClient.Security.GetAPIKey(
		esClient.Security.GetAPIKey.WithName(apiKeyName),
		esClient.Security.GetAPIKey.WithActiveOnly(true),
	)

	if err != nil || getRes.IsError() {
		return nil
	}
	defer getRes.Body.Close()
	var getResp GetAPIKeysResponse

	if err := json.NewDecoder(getRes.Body).Decode(&getResp); err != nil {
		return nil
	}
	return getResp.APIKeys
}
func ApiKeyIDExist(cli client.Client, ctx context.Context, esClient *elasticsearch.Client, req ctrl.Request, apikey v1alpha1.ElasticsearchApikey) bool {

	apikeyID, err := GetAPIKeyID(cli, ctx, req, apikey)
	if err != nil {
		return false
	}
	getRes, err := esClient.Security.GetAPIKey(
		esClient.Security.GetAPIKey.WithID(apikeyID),
		esClient.Security.GetAPIKey.WithActiveOnly(true),
	)

	if err != nil || getRes.IsError() {
		return false
	}
	defer getRes.Body.Close()
	return true
}

func ApiKeyNameExist(cli client.Client, ctx context.Context, esClient *elasticsearch.Client, apiKeyName string) bool {

	getRes, err := esClient.Security.GetAPIKey(
		esClient.Security.GetAPIKey.WithName(apiKeyName),
		esClient.Security.GetAPIKey.WithActiveOnly(true),
	)

	if err != nil {
		return false
	}
	defer getRes.Body.Close()

	if getRes.IsError() {
		return false
	}
	var getResp GetAPIKeysResponse

	if err := json.NewDecoder(getRes.Body).Decode(&getResp); err != nil {
		return false
	}

	// Step 2: Check if some keys already exists
	keyExists := (len(getResp.APIKeys) > 0)

	return keyExists
}
func CreateApikey(cli client.Client, ctx context.Context, esClient *elasticsearch.Client, apikey *v1alpha1.ElasticsearchApikey, req ctrl.Request) (ctrl.Result, error) {
	response, err := esClient.Security.CreateAPIKey(
		strings.NewReader(apikey.Spec.Body),
		esClient.Security.CreateAPIKey.WithContext(ctx),
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
		return utils.GetRequeueResult(), fmt.Errorf("error creating API key Secret: %v", &err)
	}

	apikey.Status.APIKeyID = apikeyId
	//if err := cli.Status().Update(ctx, &apikey); err != nil {
	//	return utils.GetRequeueResult(), fmt.Errorf("error updating API key status: %s", response.String())
	//}

	return utils.GetRequeueResult(), nil
}

func GetAPIKeyID(cli client.Client, ctx context.Context, req ctrl.Request, apikey v1alpha1.ElasticsearchApikey) (string, error) {
	if sec, err := GetAPIKeySecret(cli, ctx, req.Namespace, req.Name); err == nil {
		if id, ok := sec.Data["id"]; ok {
			return string(id), nil
		}
		return "", fmt.Errorf("secret %s/%s found but missing 'id' field", req.Namespace, req.Name)
	}

	if len(apikey.Status.APIKeyID) > 0 {
		return apikey.Status.APIKeyID, nil
	}

	return "", fmt.Errorf("neither secret %s/%s nor in CRD status provided API key id", req.Namespace, req.Name)

}

func CreateApikeyold(cli client.Client, ctx context.Context, esClient *elasticsearch.Client, apikey v1alpha1.ElasticsearchApikey, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	sec, err := GetAPIKeySecret(cli, ctx, req.Namespace, req.Name)
	if err != nil {
		logger.Info("Apikey secret %s not found", req.Name)
	}
	apikeyId := string(sec.Data["id"])

	secretExists := (sec.Data != nil)

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

	var getResp GetAPIKeysResponse

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

			apiBody, _ := removeField(apikey.Spec.Body, "name")

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
			esClient.Security.CreateAPIKey.WithContext(ctx),
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
			return utils.GetRequeueResult(), fmt.Errorf("error creating API key Secret: %v", &err)
		}
		//apikey.Status.APIKeyID = apikeyId
		if err := cli.Status().Update(ctx, &apikey); err != nil {
			return utils.GetRequeueResult(), fmt.Errorf("error updating API key status: %s", response.String())
		}
	}

	return utils.GetRequeueResult(), nil
}

func GetAPIKeySecret(cli client.Client, ctx context.Context, namespace string, secretName string) (*k8sv1.Secret, error) {
	key := client.ObjectKey{Namespace: namespace, Name: secretName}
	var sec k8sv1.Secret
	if err := cli.Get(ctx, key, &sec); err != nil {
		return nil, err
	}
	return &sec, nil
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

func containsID(apiKeys []APIKey, id string) bool {
	for _, k := range apiKeys {
		if k.ID == id {
			return true
		}
	}
	return false
}

func removeField(input string, field string) (string, error) {
	var data map[string]interface{}

	if err := json.Unmarshal([]byte(input), &data); err != nil {
		return "", err
	}
	delete(data, field)
	output, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "", err
	}

	return string(output), nil
}
