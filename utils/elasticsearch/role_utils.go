package elasticsearch

import (
	"eck-custom-resources/api/es.eck/v1alpha1"
	"eck-custom-resources/utils"
	"strings"

	"github.com/elastic/go-elasticsearch/v8"
	ctrl "sigs.k8s.io/controller-runtime"
)

func DeleteRole(esClient *elasticsearch.Client, roleName string) (ctrl.Result, error) {
	res, err := esClient.Security.DeleteRole(roleName)
	if err != nil || res.IsError() {
		return utils.GetRequeueResult(), err
	}
	return ctrl.Result{}, nil
}

func UpsertRole(esClient *elasticsearch.Client, role v1alpha1.ElasticsearchRole) (ctrl.Result, error) {
	res, err := esClient.Security.PutRole(role.Name, strings.NewReader(role.Spec.Body))

	if err != nil || res.IsError() {
		return utils.GetRequeueResult(), GetClientErrorOrResponseError(err, res)
	}

	return ctrl.Result{}, nil
}
