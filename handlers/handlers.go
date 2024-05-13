package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"

	"github.com/de-wan/project_management_apis/db_sqlc"
	"github.com/de-wan/project_management_apis/utils"
	"golang.org/x/crypto/bcrypt"
)

type Response struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Parse form data
	err := r.ParseForm()
	if err != nil {
		log.Println(err)
		resp := Response{
			Code:    1,
			Message: "Error parsing form data",
		}
		json.NewEncoder(w).Encode(resp)
		return
	}

	// validate data
	c := context.Background()
	queries := db_sqlc.New(db_sqlc.DB)

	type RegisterErrors struct {
		Username        []string `json:"username"`
		Email           []string `json:"email"`
		Phone           []string `json:"phone"`
		Password        []string `json:"password"`
		ConfirmPassword []string `json:"confirm_password"`
	}

	hasErrors := false
	registerErrors := RegisterErrors{}

	if r.FormValue("username") == "" {
		hasErrors = true
		registerErrors.Username = append(registerErrors.Username, "This field is required")
	}

	if r.FormValue("email") == "" {
		hasErrors = true
		registerErrors.Email = append(registerErrors.Email, "This field is required")
	}

	if r.FormValue("phone") == "" {
		hasErrors = true
		registerErrors.Phone = append(registerErrors.Phone, "This field is required")
	}

	if r.FormValue("password") == "" {
		hasErrors = true
		registerErrors.Password = append(registerErrors.Password, "This field is required")
	}

	if r.FormValue("confirm_password") == "" {
		hasErrors = true
		registerErrors.ConfirmPassword = append(registerErrors.ConfirmPassword, "This field is required")
	}

	// check username is unique
	isUsernameTaken, err := queries.IsUsernameTaken(c, r.FormValue("username"))
	if err != nil {
		log.Println(err)
		resp := Response{
			Code:    1,
			Message: "Error validating username uniqueness",
		}
		json.NewEncoder(w).Encode(resp)
		return
	}
	if isUsernameTaken == 1 {
		hasErrors = true
		registerErrors.Username = append(registerErrors.Username, "This username is already taken")
	}

	// check email is unique
	isEmailTaken, err := queries.IsEmailTaken(c, r.FormValue("email"))
	if err != nil {
		log.Println(err)
		resp := Response{
			Code:    1,
			Message: "Error validating email uniqueness",
		}
		json.NewEncoder(w).Encode(resp)
		return
	}
	if isEmailTaken == 1 {
		hasErrors = true
		registerErrors.Email = append(registerErrors.Email, "This email is already taken")
	}

	// check email is unique
	isPhoneTaken, err := queries.IsPhoneTaken(c, r.FormValue("phone"))
	if err != nil {
		log.Println(err)
		resp := Response{
			Code:    1,
			Message: "Error validating phone uniqueness",
		}
		json.NewEncoder(w).Encode(resp)
		return
	}
	if isPhoneTaken == 1 {
		hasErrors = true
		registerErrors.Phone = append(registerErrors.Phone, "This phone is already taken")
	}

	// check password length
	if len(r.FormValue("password")) < 7 {
		hasErrors = true
		registerErrors.Password = append(registerErrors.Password, "Password must have atleast 7 characters")
	}

	// check if password matches
	if r.FormValue("password") != r.FormValue("confirm_password") {
		hasErrors = true
		registerErrors.ConfirmPassword = append(registerErrors.ConfirmPassword, "Passwords do not match")
	}

	// return errors
	if hasErrors {
		resp := Response{
			Code:    1,
			Message: "Please correct form errors",
			Data:    registerErrors,
		}
		json.NewEncoder(w).Encode(resp)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(r.FormValue("password")), bcrypt.DefaultCost)
	if err != nil {
		log.Println(err)
		resp := Response{
			Code:    1,
			Message: "Error hashing password",
		}
		json.NewEncoder(w).Encode(resp)
		return
	}

	err = queries.RegisterUser(c, db_sqlc.RegisterUserParams{
		Uuid:     utils.GenerateUUID(),
		Username: r.FormValue("username"),
		Email:    r.FormValue("email"),
		Phone:    r.FormValue("phone"),
		Password: string(hashedPassword),
	})
	if err != nil {
		log.Println(err)
		resp := Response{
			Code:    1,
			Message: "Error hashing password",
		}
		json.NewEncoder(w).Encode(resp)
		return
	}

	response := Response{
		Code:    0,
		Message: "User registered successfully",
	}

	json.NewEncoder(w).Encode(response)
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Parse form data
	err := r.ParseForm()
	if err != nil {
		log.Println(err)
		resp := Response{
			Code:    1,
			Message: "Error parsing form data",
		}
		json.NewEncoder(w).Encode(resp)
		return
	}

	// validate data
	c := context.Background()
	queries := db_sqlc.New(db_sqlc.DB)

	type LoginErrors struct {
		UsernameOrEmail []string `json:"username_or_email"`
		Password        []string `json:"password"`
	}

	hasErrors := false
	var loginErrors LoginErrors

	if r.FormValue("username_or_email") == "" {
		loginErrors.UsernameOrEmail = append(loginErrors.UsernameOrEmail, "This field is required")
	}

	if r.FormValue("password") == "" {
		loginErrors.Password = append(loginErrors.Password, "This field is required")
	}

	if hasErrors {
		resp := Response{
			Code:    1,
			Message: "Please correct form errors",
			Data:    loginErrors,
		}
		json.NewEncoder(w).Encode(resp)
		return
	}

	savedPassword, err := queries.GetUserPasswordForLogin(c, db_sqlc.GetUserPasswordForLoginParams{
		Username: r.FormValue("username_or_email"),
		Email:    r.FormValue("username_or_email"),
	})
	if err != nil {
		if err == sql.ErrNoRows {
			resp := Response{
				Code:    1,
				Message: "Invalid login credentials",
			}
			json.NewEncoder(w).Encode(resp)
			return
		}
		log.Println(err)
		resp := Response{
			Code:    1,
			Message: "Unable to validate login credentials",
		}
		json.NewEncoder(w).Encode(resp)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(savedPassword), []byte(r.FormValue("password")))
	if err != nil {
		resp := Response{
			Code:    1,
			Message: "Invalid login credentials",
		}
		json.NewEncoder(w).Encode(resp)
		return
	}

	// todo: generate jwt

}
