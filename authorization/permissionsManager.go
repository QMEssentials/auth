package authorization

import "auth/repositories"

type PermissionsManager struct {
	userRepo *repositories.UserRepository
}

func NewPermissionsManager(userRepo *repositories.UserRepository) *PermissionsManager {
	return &PermissionsManager{userRepo: userRepo}
}

func (pm *PermissionsManager) GetPermittedOperationsForRoles(roles []string) []string {
	permissions := map[string]struct{}{}
	for _, role := range roles {
		if role == "Administrator" {
			permissions["Create a User"] = struct{}{}
		}
		//The idea is to add to this structure as new roles and permissions become available
		//Eventually it should probably become a table or something
	}
	keys := make([]string, 0, len(permissions))
	for k := range permissions {
		keys = append(keys, k)
	}
	return keys
}
