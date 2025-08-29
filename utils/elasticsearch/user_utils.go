package elasticsearch

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"eck-custom-resources/api/es.eck/v1alpha1"
	"eck-custom-resources/utils"

	"github.com/elastic/go-elasticsearch/v8"
	k8sv1 "k8s.io/api/core/v1"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type User struct {
	Username   string                 `json:"username"`
	Roles      []string               `json:"roles"`
	FullName   string                 `json:"full_name,omitempty"`
	Email      string                 `json:"email,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
	Enabled    bool                   `json:"enabled"`
	ProfileUID string                 `json:"profile_uid,omitempty"`
}

func GetUser(esClient *elasticsearch.Client, username string) (*User, error) {
	// Check if user exists
	res, err := esClient.Security.GetUser(
		esClient.Security.GetUser.WithUsername(username),
		esClient.Security.GetUser.WithContext(context.Background()))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	var payload map[string]User
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	u, ok := payload["username"]
	if !ok {
		return nil, err
	}
	return &u, nil

}
func DeleteUser(esClient *elasticsearch.Client, userName string) (ctrl.Result, error) {
	res, err := esClient.Security.DeleteUser(userName)
	if err != nil || res.IsError() {
		return utils.GetRequeueResult(), err
	}
	return ctrl.Result{}, nil
}

func UpsertUser(esClient *elasticsearch.Client, cli client.Client, ctx context.Context, user v1alpha1.ElasticsearchUser) (ctrl.Result, error) {
	var secret k8sv1.Secret

	// Inject password field with data from given secret
	err := getUserSecret(cli, ctx, user.Namespace, user, &secret)
	if err != nil {
		return utils.GetRequeueResult(), err
	}
	var password = secret.Data[user.Name]

	var userBody map[string]interface{}
	unmarshallErr := json.Unmarshal([]byte(user.Spec.Body), &userBody)
	if unmarshallErr != nil {
		return ctrl.Result{}, unmarshallErr
	}

	userBody["password"] = string(password)
	userWithPassword, marshallErr := json.Marshal(userBody)
	if marshallErr != nil {
		return ctrl.Result{}, marshallErr
	}

	res, err := esClient.Security.PutUser(user.Name, strings.NewReader(string(userWithPassword)))
	if err != nil || res.IsError() {
		return utils.GetRequeueResult(), GetClientErrorOrResponseError(err, res)
	}
	return ctrl.Result{}, nil
}

func getUserSecret(cli client.Client, ctx context.Context, namespace string, user v1alpha1.ElasticsearchUser, secret *k8sv1.Secret) error {
	if err := cli.Get(ctx, client.ObjectKey{Namespace: namespace, Name: user.Spec.SecretName}, secret); err != nil {
		return err
	}
	return nil
}
