package authorization

import (
	"auth/models"
	"auth/repositories"
	"strings"
)

type PermissionsManager struct {
	userRepo    *repositories.UserRepository
	permissions *[]models.Permission
}

func NewPermissionsManager(userRepo *repositories.UserRepository) *PermissionsManager {
	permissions := []models.Permission{
		{CanonicalName: "user-create", DisplayName: "Create a User", Roles: []string{"Administrator"}},
		{CanonicalName: "user-search", DisplayName: "Search for Users", Roles: []string{"Administrator"}},
		{CanonicalName: "product-create", DisplayName: "Create a Product", Roles: []string{"Administrator"}},
		{CanonicalName: "product-search", DisplayName: "Search for Products", Roles: []string{"Administrator"}},
		{CanonicalName: "product-view", DisplayName: "View a Product", Roles: []string{"Administrator"}},
		{CanonicalName: "product-edit", DisplayName: "Edit a Product", Roles: []string{"Administrator"}},
	}
	return &PermissionsManager{userRepo: userRepo, permissions: &permissions}
}

func (pm *PermissionsManager) IsAllowed(userId string, requestedPermission string) (bool, error) {
	user, err := pm.userRepo.Select(userId)
	if err != nil {
		return false, err
	}
	for _, allowedPermission := range *pm.permissions {
		if allowedPermission.CanonicalName == requestedPermission {
			for _, allowedRole := range allowedPermission.Roles {
				for _, userRole := range user.Roles {
					if strings.EqualFold(allowedRole, userRole) {
						return true, nil
					}
				}
			}
		}
	}
	return false, nil
}

func (pm *PermissionsManager) GetPermittedOperationsForRoles(roles []string) []string {
	confirmedPermissions := make([]models.Permission, 0)
	for _, permission := range *pm.permissions {
		alreadyAdded := false
		for _, confirmedPermission := range confirmedPermissions {
			if permission.CanonicalName == confirmedPermission.CanonicalName {
				alreadyAdded = true
				break
			}
		}
		if alreadyAdded {
			break
		}
		isAllowed := false
		for _, allowedRole := range permission.Roles {
			for _, userRole := range roles {
				if strings.EqualFold(allowedRole, userRole) {
					isAllowed = true
					break
				}
			}
			if isAllowed {
				break
			}
		}
		if isAllowed {
			confirmedPermissions = append(confirmedPermissions, permission)
		}
	}
	results := make([]string, len(confirmedPermissions))
	for _, confirmedPermission := range confirmedPermissions {
		results = append(results, confirmedPermission.DisplayName)
	}
	return results
}
