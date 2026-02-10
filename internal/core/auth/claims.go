package auth

import (
	"github.com/nevzatcirak/shyntr/internal/data/models"
)

func MapUserClaims(user *models.User, scopes []string) map[string]interface{} {
	claims := make(map[string]interface{})

	claims["sub"] = user.ID
	claims["updated_at"] = user.UpdatedAt.Unix()

	for _, scope := range scopes {
		switch scope {
		case "profile":
			claims["name"] = user.FirstName + " " + user.LastName
			claims["given_name"] = user.FirstName
			claims["family_name"] = user.LastName
			claims["nickname"] = user.FirstName
			// claims["birthdate"] = user.BirthDate.Format("2006-01-02")

		case "email":
			claims["email"] = user.Email
			claims["email_verified"] = true
		case "phone":
			if user.PhoneNumber != "" {
				claims["phone_number"] = user.PhoneNumber
				claims["phone_number_verified"] = false
			}

		case "address":
			if user.Address != "" {
				claims["address"] = map[string]string{
					"formatted": user.Address,
				}
			}

		case "shyntr.admin":
			if user.Role == "admin" {
				claims["is_admin"] = true
			}
		}
	}

	return claims
}
