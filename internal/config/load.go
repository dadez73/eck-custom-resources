// internal/config/load.go
package config

import (
	"errors"
	"os"
	"path/filepath"

	"sigs.k8s.io/yaml"
	//"gopkg.in/yaml.v3"
	appv2 "eck-custom-resources/api/config/v2"
)

func defaultSpec() appv2.ProjectConfigSpec {
	return appv2.ProjectConfigSpec{
		Elasticsearch: appv2.ElasticsearchSpec{
			Url: "https://es.gecodev.eoc.ch",
			Authentication: &appv2.ElasticsearchAuthentication{
				UsernamePassword: &appv2.UsernamePasswordAuthentication{
					SecretName: "gecodev-eck-es-elastic-user",
					UserName:   "elastic",
				},
			},
			Certificate: &appv2.PublicCertificate{
				SecretName:     "quickstart-es-http-certs-public",
				CertificateKey: "ca.crt",
			},
		},
		Kibana: appv2.KibanaSpec{
			Url: "https://kibana.gecodev.eoc.ch",
			Authentication: &appv2.KibanaAuthentication{
				UsernamePassword: &appv2.UsernamePasswordAuthentication{
					SecretName: "gecodev-eck-kb-kb-http",
					UserName:   "elastic",
				},
			},
			Certificate: &appv2.PublicCertificate{
				SecretName:     "quickstart-kb-http-certs-public",
				CertificateKey: "ca.crt",
			},
		},
	}
}

func Validate(spec *appv2.ProjectConfigSpec) error {
	if spec.Elasticsearch.Url == "" {
		return errors.New("elasticsearch.endpoint is required")
	}
	if spec.Kibana.Url == "" {
		return errors.New("kibana.url is required")
	}
	return nil
}

func LoadProjectConfigSpec(path string) (appv2.ProjectConfigSpec, error) {
	spec := defaultSpec()
	if path == "" {
		return spec, nil
	}

	abs, _ := filepath.Abs(path)
	b, err := os.ReadFile(abs)
	if err != nil {
		return spec, err
	}

	// Optional: expand ${ENV_VAR} placeholders in the YAML
	expanded := []byte(os.ExpandEnv(string(b)))

	if err := yaml.Unmarshal(expanded, &spec); err != nil {
		return spec, err
	}
	if err := Validate(&spec); err != nil {
		return spec, err
	}
	return spec, nil
}
