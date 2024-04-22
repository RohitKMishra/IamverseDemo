package util

import (
	"regexp"

	"github.com/RohitKMishra/IamverseDemo/models"

	valid "github.com/asaskevich/govalidator"
)

// IsEmpty checks if a string is empty
func IsEmpty(str string) (bool, string) {
	if valid.HasWhitespaceOnly(str) && str != "" {
		return true, "Must not be empty"
	}

	return false, ""
}

// ValidateRegister func validates the body of user for registration
func ValidateRegister(u *models.User) *models.UserErrors {
	e := &models.UserErrors{}
	e.Err, e.Countrycode = IsEmpty(u.Countrycode)

	for _, email := range u.Emails {
		if !valid.IsEmail(email) {
			e.Err, e.Email = true, "Must be a valid email"
		}
	}
	re := regexp.MustCompile("\\d") // regex check for at least one integer in string
	if !(len(u.Password) >= 8 && valid.HasLowerCase(u.Password) && valid.HasUpperCase(u.Password) && re.MatchString(u.Password)) {
		e.Err, e.Password = true, "Length of password should be atleast 8 and it must be a combination of uppercase letters, lowercase letters and numbers"
	}

	return e
}

// func ValidateSocialLogin(firstname, lastname, email string) validationResult {
// 	e := &models.UserErrors{}

// 	if !valid.IsEmail(email) {
// 		e.Err, e.Email = true, "Must be a valid email"
// 	}
// 	if firstname == "" {
// 		e.Err, e.Firstname = IsEmpty(firstname)

// 	}
// 	if lastname == "" {
// 		e.Err, e.Lastname = IsEmpty(lastname)

// 	}

// 	return e
// }

func ValidateSocialLogin(firstname, lastname, email string) ValidatorResult {
	validationResult := ValidatorResult{}

	if !valid.IsEmail(email) {
		validationResult.Valid = false
		validationResult.Message = "Invalid email format"
	}

	if firstname == "" {
		validationResult.Valid = false
		validationResult.Message = "Firstname cannot be empty"
	}

	if lastname == "" {
		validationResult.Valid = false
		validationResult.Message = "Lastname cannot be empty"
	}

	return validationResult
}

// ValidatorResult represents the result of input validation.
type ValidatorResult struct {
	Valid   bool   // Indicates whether the validation is successful
	Message string // Contains a validation message (error message) if validation fails
}

// ValidateInput validates the input fields.
// func ValidateLoginInput(email string) ValidatorResult {

// 	// Check if the email is in a valid format using a basic regex pattern.
// 	emailPattern := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}$`
// 	match, _ := regexp.MatchString(emailPattern, email)
// 	if !match {
// 		return ValidatorResult{false, "Invalid email format"}
// 	}

// 	return ValidatorResult{true, "Validation successful"}
// }

func ValidateLoginInput(email string) ValidatorResult {
	// Check if the email is in a valid format using a commonly used regex pattern.
	emailPattern := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	match, _ := regexp.MatchString(emailPattern, email)
	if !match {
		return ValidatorResult{false, "Invalid email format"}
	}

	return ValidatorResult{true, "Validation successful"}
}
