// Copyright 2024 Gravitational, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package notifications

import (
	"context"
	"log/slog"
	"slices"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/api/client"
	apidefaults "github.com/gravitational/teleport/api/defaults"
	notificationsv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/notifications/v1"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/authz"
	"github.com/gravitational/teleport/lib/services"
)

// ServiceConfig holds configuration options for the notifications gRPC service.
type ServiceConfig struct {
	// Backend is the backend used to store Kubernetes waiting containers.
	Backend services.Notifications

	// Authorizer is the authorizer used to check access to resources.
	Authorizer authz.Authorizer

	// Getters is the AuthServer methods needed by the notifications gRPC service.
	Getters Getters
}

// Getters defines AuthServer methods needed by the notifications gRPC service.
type Getters interface {
	ListNotificationsForUser(ctx context.Context,
		username string,
		pageSize int,
		userNotificationsStartKey string,
		globalNotificationsStartKey string,
		userNotificationMatchFn func(*notificationsv1.Notification) bool,
		globalNotificationMatchFn func(*notificationsv1.GlobalNotification) bool) ([]*notificationsv1.Notification, string, string, error)
	ListUserNotificationStates(ctx context.Context, username string, pageSize int, startKey string) ([]*notificationsv1.UserNotificationState, string, error)
	GetUserLastSeenNotification(ctx context.Context, username string) (*notificationsv1.UserLastSeenNotification, error)

	// Needed by the ReviewPermissionChecker
	services.UserLoginStatesGetter
	services.UserGetter
	services.RoleGetter
	client.ListResourcesClient
	GetRoles(ctx context.Context) ([]types.Role, error)
	GetClusterName(opts ...services.MarshalOption) (types.ClusterName, error)
}

// Service implements the teleport.notications.v1.NotificationsService RPC Service.
type Service struct {
	notificationsv1.UnimplementedNotificationServiceServer

	authorizer authz.Authorizer
	backend    services.Notifications
	getters    Getters
}

// NewService returns a new notificationns gRPC service.
func NewService(cfg ServiceConfig) (*Service, error) {
	switch {
	case cfg.Backend == nil:
		return nil, trace.BadParameter("server with roles is required")
	case cfg.Authorizer == nil:
		return nil, trace.BadParameter("authorizer is required")
	case cfg.Getters == nil:
		return nil, trace.BadParameter("getters are required")
	}

	return &Service{
		authorizer: cfg.Authorizer,
		backend:    cfg.Backend,
		getters:    cfg.Getters,
	}, nil
}

// ListNotifications returns a paginated list of notifications which match the user.
func (s *Service) ListNotifications(ctx context.Context, req *notificationsv1.ListNotificationsRequest) (*notificationsv1.ListNotificationsResponse, error) {
	authCtx, err := s.authorizer.Authorize(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	username := authCtx.User.GetName()

	// Fetch all of the user's notification states. We do this upfront to filter out dismissed notifications.
	var notificationStates []*notificationsv1.UserNotificationState
	var startKey string
	for {
		usn, nextKey, err := s.backend.ListUserNotificationStates(ctx, username, apidefaults.DefaultChunkSize, startKey)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		notificationStates = append(notificationStates, usn...)

		if nextKey == "" {
			break
		}
		startKey = nextKey
	}

	notificationStatesMap := make(map[string]notificationsv1.NotificationState, len(notificationStates))
	for _, notificationState := range notificationStates {
		if notificationState.Spec != nil && notificationState.Status != nil {
			notificationStatesMap[notificationState.Spec.NotificationId] = notificationState.Status.GetNotificationState()
		}
	}

	var userNotifMatchFn = func(n *notificationsv1.Notification) bool {
		// Return true if the user hasn't dismissed this notification
		return notificationStatesMap[n.GetMetadata().GetName()] != notificationsv1.NotificationState_NOTIFICATION_STATE_DISMISSED
	}

	var globalNotifMatchFn = func(gn *notificationsv1.GlobalNotification) bool {
		// If the user has dismissed this notification, return false.
		if notificationStatesMap[gn.GetMetadata().GetName()] == notificationsv1.NotificationState_NOTIFICATION_STATE_DISMISSED {
			return false
		}

		switch matcher := gn.Spec.Matcher.(type) {
		case *notificationsv1.GlobalNotificationSpec_All:
			// Always return true if the matcher is "all."
			return true

		case *notificationsv1.GlobalNotificationSpec_ByRoles:
			matcherRoles := matcher.ByRoles.GetRoles()
			userRoles := authCtx.User.GetRoles()

			// If MatchAllConditions is true, then userRoles must contain every role in matcherRoles.
			if gn.Spec.MatchAllConditions {
				for _, matcherRole := range matcherRoles {
					// Return false if there is any role missing.
					if !slices.Contains(userRoles, matcherRole) {
						return false
					}
				}
				return true
			}

			// Return true if it matches at least one matcherRole.
			for _, matcherRole := range matcherRoles {
				if slices.Contains(userRoles, matcherRole) {
					return true
				}
			}

			return false

		case *notificationsv1.GlobalNotificationSpec_ByPermissions:
			roleConditionsList := matcher.ByPermissions.GetRoleConditions()

			var results []bool
			for _, roleConditions := range roleConditionsList {
				match, err := s.matchRoleConditions(ctx, roleConditions)
				if err != nil {
					slog.WarnContext(ctx, "Encountered error while matching RoleConditions", "role_conditions", roleConditions, "error", err)
					return false
				}

				// If MatchAllConditions is false, we can exit at the first match.
				if !gn.Spec.MatchAllConditions && match {
					return true
				}

				// If MatchAllConditions is true, we exit at the first non-match.
				if gn.Spec.MatchAllConditions && !match {
					return false
				}

				results = append(results, match)
			}

			// Return false if any of the roleConditions didn't match.
			if gn.Spec.MatchAllConditions {
				return !slices.Contains(results, false)
			}

			return false
		}

		return false
	}

	pageSize := int(req.PageSize)
	userNotificationsStartKey := req.UserNotificationsPageToken
	globalNotificationsStartKey := req.GlobalNotificationsPageToken

	notifications, userNotificationsNextKey, globalNotificationsNextKey, err := s.getters.ListNotificationsForUser(ctx,
		username,
		pageSize,
		userNotificationsStartKey,
		globalNotificationsStartKey,
		userNotifMatchFn,
		globalNotifMatchFn)

	if err != nil {
		return nil, trace.Wrap(err)
	}

	userLastSeenNotification, err := s.getters.GetUserLastSeenNotification(ctx, username)
	if err != nil && !trace.IsNotFound(err) {
		return nil, trace.Wrap(err)
	}

	// Add label to indicate notifications that the user has clicked.
	for _, notification := range notifications {
		if (notificationStatesMap[notification.GetMetadata().GetName()]) == notificationsv1.NotificationState_NOTIFICATION_STATE_CLICKED {
			notification.GetMetadata().Labels[types.NotificationClickedLabel] = "true"
		}
	}

	response := &notificationsv1.ListNotificationsResponse{
		Notifications:                     notifications,
		UserNotificationsNextPageToken:    userNotificationsNextKey,
		GlobalNotificationsNextPageToken:  globalNotificationsNextKey,
		UserLastSeenNotificationTimestamp: userLastSeenNotification.GetStatus().GetLastSeenTime(),
	}

	return response, nil
}

func (s *Service) matchRoleConditions(ctx context.Context, rc *types.RoleConditions) (bool, error) {
	authCtx, err := s.authorizer.Authorize(ctx)
	if err != nil {
		return false, trace.Wrap(err)
	}

	if len(rc.Logins) > 0 {
		userLogins := authCtx.Checker.GetAllLogins()
		var matchedLogin bool
		for _, login := range rc.Logins {
			// If at least one  of the logins match, this is a match.
			if slices.Contains(userLogins, login) {
				matchedLogin = true
				break
			}
		}
		if !matchedLogin {
			return false, nil
		}
	}

	if len(rc.Rules) > 0 {
		var matchedRule bool
		for _, rule := range rc.Rules {
			hasAccess, err := s.checkAccessToRule(ctx, rule)
			if err != nil {
				return false, trace.WrapWithMessage(err, "encountered unexpected error when checking access to rule")
			}

			// If the user has permissions for at least one of the rules, this is a match.
			if hasAccess {
				matchedRule = true
				break
			}
		}
		if !matchedRule {
			return false, nil
		}
	}

	if rc.ReviewRequests != nil {
		identity := authCtx.Identity.GetIdentity()
		checker, err := services.NewReviewPermissionChecker(
			ctx,
			s.getters,
			authCtx.User.GetName(),
			&identity,
		)
		if err != nil {
			return false, trace.Wrap(err)
		}

		// unless the user has allow directives for reviewing, they will never be able to
		// see any requests other than their own.
		if !checker.HasAllowDirectives() {
			return false, nil
		}

		// We instantiate a fake access request with the defined roles, this allows us to use our existing AccessReviewChecker to check if the
		// user is allowed to review requests for them.
		fakeAccessRequest, err := types.NewAccessRequest("fake", "fake", rc.ReviewRequests.Roles...)
		if err != nil {
			return false, trace.Wrap(err)
		}

		canReview, err := checker.CanReviewRequest(fakeAccessRequest)
		if err != nil {
			return false, trace.WrapWithMessage(err, "failed to evaluate request review permissions")
		}

		if !canReview {
			return false, nil
		}
	}

	// This RoleConditions object matches if there were no failed matches that returned prior to this.
	return true, nil
}

// checkAccessToRule returns true if the user has the permissions defined in a rule.
func (s *Service) checkAccessToRule(ctx context.Context, rule types.Rule) (bool, error) {
	authCtx, err := s.authorizer.Authorize(ctx)
	if err != nil {
		return false, trace.Wrap(err)
	}

	for _, resourceKind := range rule.Resources {
		for _, verb := range rule.Verbs {
			if err := authCtx.CheckAccessToKind(resourceKind, verb); err != nil {
				// If the user doesn't have access for the verbs for any one of the resources in the rule, then just return false.
				if trace.IsAccessDenied(err) {
					return false, nil
					// If the error is due to something else, then return it.
				} else {
					return false, trace.Wrap(err)
				}
			}
		}
	}

	return true, nil
}

// UpsertUserNotificationState creates or updates a user notification state which records whether the user has clicked on or dismissed a notification.
func (s *Service) UpsertUserNotificationState(ctx context.Context, req *notificationsv1.UpsertUserNotificationStateRequest) (*notificationsv1.UserNotificationState, error) {
	if req.Username == "" {
		return nil, trace.BadParameter("missing username")
	}
	if req.UserNotificationState == nil {
		return nil, trace.BadParameter("missing notification state")
	}

	authCtx, err := s.authorizer.Authorize(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	username := authCtx.User.GetName()
	if username != req.Username {
		return nil, trace.AccessDenied("a user may only update their own notification state")
	}

	out, err := s.backend.UpsertUserNotificationState(ctx, req.Username, req.UserNotificationState)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return out, nil
}

// UpsertUserLastSeenNotification creates or updates a user's last seen notification timestamp.
func (s *Service) UpsertUserLastSeenNotification(ctx context.Context, req *notificationsv1.UpsertUserLastSeenNotificationRequest) (*notificationsv1.UserLastSeenNotification, error) {
	if req.Username == "" {
		return nil, trace.BadParameter("missing username")
	}
	if req.UserLastSeenNotification == nil {
		return nil, trace.BadParameter("missing user last seen notification")
	}

	authCtx, err := s.authorizer.Authorize(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	username := authCtx.User.GetName()
	if username != req.Username {
		return nil, trace.AccessDenied("a user may only update their own last seen notification timestamp")
	}

	out, err := s.backend.UpsertUserLastSeenNotification(ctx, req.Username, req.UserLastSeenNotification)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return out, nil
}
