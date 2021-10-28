package domain

import "strings"

type RolePermissions struct {
	rolePermissions map[string][]string
}

func (roles RolePermissions) IsAuthorisedForRole(role string, operation string) bool {
	permissions := roles.rolePermissions[role]
	for _, p := range permissions {
		if p == strings.TrimSpace(operation) {
			return true
		}
	}
	return false
}

func GetUserRolePermissions() RolePermissions {
	// create a map of the admin and user permissions
	return RolePermissions{map[string][]string{
		"admin": {"GetAllActiveCustomer",
			"GetAllInActiveCustomer",
			"GetCustomer",
			"GetAllCustomer",
			"NewAccount",
			"NewTransaction"},
		"user": {"GetCustomer", "NewTransaction"},
	},
	}
}
