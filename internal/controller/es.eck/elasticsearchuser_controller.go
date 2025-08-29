/*
Copyright 2022.

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

package eseck

import (
	"context"
	"fmt"
	"time"

	configv2 "eck-custom-resources/api/config/v2"
	"eck-custom-resources/utils"
	esutils "eck-custom-resources/utils/elasticsearch"

	"k8s.io/client-go/tools/record"

	eseckv1alpha1 "eck-custom-resources/api/es.eck/v1alpha1"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// ElasticsearchUserReconciler reconciles a ElasticsearchUser object
type ElasticsearchUserReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	ProjectConfig configv2.ProjectConfigSpec
	Recorder      record.EventRecorder
}

//+kubebuilder:rbac:groups=es.eck.github.com,resources=elasticsearchusers,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=es.eck.github.com,resources=elasticsearchusers/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=es.eck.github.com,resources=elasticsearchusers/finalizers,verbs=update

func (r *ElasticsearchUserReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	finalizer := "elasticsearchusers.es.eck.github.com/finalizer"

	var user eseckv1alpha1.ElasticsearchUser
	if err := r.Get(ctx, req.NamespacedName, &user); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	// Keep an old copy of status for MergeFrom patches
	oldStatus := user.Status.DeepCopy()

	// Convenience locals
	desiredGen := user.GetGeneration()

	targetInstance, err := r.getTargetInstance(&user, user.Spec.TargetConfig, ctx, req.Namespace)
	if err != nil {
		return utils.GetRequeueResult(), err
	}

	if !targetInstance.Enabled {
		logger.Info("Elasticsearch reconciler disabled, not reconciling.", "Resource", req.NamespacedName)
		return ctrl.Result{}, nil
	}

	esClient, createClientErr := esutils.GetElasticsearchClient(r.Client, ctx, *targetInstance, req)
	if createClientErr != nil {
		logger.Error(createClientErr, "Failed to create Elasticsearch client")
		return utils.GetRequeueResult(), client.IgnoreNotFound(createClientErr)
	}

	if user.ObjectMeta.DeletionTimestamp.IsZero() {
		if condition := apimeta.FindStatusCondition(user.Status.Conditions, "Ready"); condition != nil {
			if condition.Status == metav1.ConditionTrue {
				var msg string
				_, err := esutils.GetUser(esClient, user.Name)
				if err != nil {
					if !apierrors.IsNotFound(err) {
						return ctrl.Result{RequeueAfter: 30 * time.Second}, err
					}
					msg = fmt.Sprintf("User %s not found", user.Name)
				}
				if user.Status.ObservedGeneration < desiredGen {
					msg = fmt.Sprintf("User %s changed", user.Name)
				}
				if len(msg) > 0 {

					userSetCondition(&user, metav1.Condition{
						Type:               "Ready",
						Status:             metav1.ConditionFalse,
						Reason:             "ReconcileNeeded",
						Message:            msg,
						ObservedGeneration: desiredGen,
						LastTransitionTime: metav1.Now(),
					})
					if perr := r.Status().Patch(ctx, &user, client.MergeFrom(&eseckv1alpha1.ElasticsearchUser{Status: *oldStatus})); perr != nil {
						r.Recorder.Event(&user, "Warning", "patching",
							fmt.Sprintf("patching status after error %v", perr))
					}
					return ctrl.Result{RequeueAfter: 10 * time.Second}, err
				}

			}
		}
		logger.Info("Creating/Updating User", "user", req.Name)
		res, err := esutils.UpsertUser(esClient, r.Client, ctx, user)

		if err != nil {
			r.Recorder.Event(&user, "Warning", "Failed to create/update",
				fmt.Sprintf("Failed to create/update %s/%s %s: %s", user.APIVersion, user.Kind, user.Name, err.Error()))

			userSetCondition(&user, metav1.Condition{
				Type:               "Error",
				Status:             metav1.ConditionFalse,
				Reason:             "ReconcileError",
				Message:            err.Error(),
				ObservedGeneration: desiredGen,
				LastTransitionTime: metav1.Now(),
			})
			if perr := r.Status().Patch(ctx, &user, client.MergeFrom(&eseckv1alpha1.ElasticsearchUser{Status: *oldStatus})); perr != nil {
				r.Recorder.Event(&user, "Warning", "patching",
					fmt.Sprintf("patching status after error %v", perr))
			}
			return ctrl.Result{RequeueAfter: 10 * time.Second}, fmt.Errorf("error creating API key Secret - Retrying: %v", &err)
		}

		r.Recorder.Event(&user, "Normal", "Created",
			fmt.Sprintf("Created/Updated %s/%s %s", user.APIVersion, user.Kind, user.Name))
		userSetCondition(&user, metav1.Condition{
			Type:               "Ready",
			Status:             metav1.ConditionTrue,
			Reason:             "Reconcile",
			Message:            "Reconciled",
			ObservedGeneration: desiredGen,
			LastTransitionTime: metav1.Now(),
		})
		if perr := r.Status().Patch(ctx, &user, client.MergeFrom(&eseckv1alpha1.ElasticsearchUser{Status: *oldStatus})); perr != nil {
			r.Recorder.Event(&user, "Warning", "patching",
				fmt.Sprintf("patching status after error %v", perr))
		}
		return res, err

	} else {
		// The object is being deleted
		if controllerutil.ContainsFinalizer(&user, finalizer) {
			logger.Info("Deleting object", "user", user.Name)
			if _, err := esutils.DeleteUser(esClient, req.Name); err != nil {
				return ctrl.Result{}, err
			}

			controllerutil.RemoveFinalizer(&user, finalizer)
			if err := r.Update(ctx, &user); err != nil {
				return ctrl.Result{}, err
			}
		}

		return ctrl.Result{}, nil
	}
	return ctrl.Result{}, nil
}

func userSetCondition(obj *eseckv1alpha1.ElasticsearchUser, c metav1.Condition) {
	// Update or add by Type
	conds := obj.Status.Conditions
	apimeta.SetStatusCondition(&conds, c)
	obj.Status.Conditions = conds
}

// SetupWithManager sets up the controller with the Manager.
func (r *ElasticsearchUserReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&eseckv1alpha1.ElasticsearchUser{}).
		WithEventFilter(utils.CommonEventFilter()).
		Complete(r)
}

func (r *ElasticsearchUserReconciler) addFinalizer(o client.Object, finalizer string, ctx context.Context) error {
	if !controllerutil.ContainsFinalizer(o, finalizer) {
		controllerutil.AddFinalizer(o, finalizer)
		if err := r.Update(ctx, o); err != nil {
			return err
		}
	}
	return nil
}

func (r *ElasticsearchUserReconciler) getTargetInstance(object runtime.Object, TargetConfig eseckv1alpha1.CommonElasticsearchConfig, ctx context.Context, namespace string) (*configv2.ElasticsearchSpec, error) {
	targetInstance := r.ProjectConfig.Elasticsearch
	if TargetConfig.ElasticsearchInstance != "" {
		var resourceInstance eseckv1alpha1.ElasticsearchInstance
		if err := esutils.GetTargetElasticsearchInstance(r.Client, ctx, namespace, TargetConfig.ElasticsearchInstance, &resourceInstance); err != nil {
			r.Recorder.Event(object, "Warning", "Failed to load target instance", fmt.Sprintf("Target instance not found: %s", err.Error()))
			return nil, err
		}

		targetInstance = resourceInstance.Spec
	}
	return &targetInstance, nil
}
