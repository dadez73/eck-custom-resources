package elasticsearch

import (
	"strings"

	"eck-custom-resources/api/es.eck/v1alpha1"
	"eck-custom-resources/utils"

	"github.com/elastic/go-elasticsearch/v8"
	ctrl "sigs.k8s.io/controller-runtime"
)

func DeleteComponentTemplate(esClient *elasticsearch.Client, componentTemplateName string) (ctrl.Result, error) {
	res, err := esClient.Cluster.DeleteComponentTemplate(componentTemplateName)
	if err != nil || res.IsError() {
		return utils.GetRequeueResult(), err
	}
	return ctrl.Result{}, nil
}

func UpsertComponentTemplate(esClient *elasticsearch.Client, componentTemplate v1alpha1.ComponentTemplate) (ctrl.Result, error) {

	res, err := esClient.Cluster.PutComponentTemplate(componentTemplate.Name, strings.NewReader(componentTemplate.Spec.Body))
	if err != nil || res.IsError() {
		return utils.GetRequeueResult(), GetClientErrorOrResponseError(err, res)
	}

	return ctrl.Result{}, nil
}

func ComponentTemplateExists(esClient *elasticsearch.Client, indexTemplateName string) (bool, error) {

	res, err := esClient.Cluster.ExistsComponentTemplate(indexTemplateName)
	if err != nil {
		return false, err
	}
	if res.StatusCode <= 299 {
		return true, nil
	}
	if res.StatusCode == 404 {
		return false, nil
	}

	return false, GetClientErrorOrResponseError(nil, res)
}
