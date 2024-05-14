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

type RegisterBody struct {
	Username        string `json:"username"`
	Email           string `json:"email"`
	Phone           string `json:"phone"`
	Password        string `json:"password"`
	ConfirmPassword string `json:"confirm_password"`
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// parse json body
	var inpJson RegisterBody
	err := json.NewDecoder(r.Body).Decode(&inpJson)
	if err != nil {
		log.Println(err)
		resp := Response{
			Code:    1,
			Message: "Unable to parse json body",
		}
		w.WriteHeader(http.StatusInternalServerError)
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

	if inpJson.Username == "" {
		hasErrors = true
		registerErrors.Username = append(registerErrors.Username, "This field is required")
	}

	if inpJson.Email == "" {
		hasErrors = true
		registerErrors.Email = append(registerErrors.Email, "This field is required")
	}

	if inpJson.Phone == "" {
		hasErrors = true
		registerErrors.Phone = append(registerErrors.Phone, "This field is required")
	}

	if inpJson.Password == "" {
		hasErrors = true
		registerErrors.Password = append(registerErrors.Password, "This field is required")
	}

	if inpJson.ConfirmPassword == "" {
		hasErrors = true
		registerErrors.ConfirmPassword = append(registerErrors.ConfirmPassword, "This field is required")
	}

	// check username is unique
	isUsernameTaken, err := queries.IsUsernameTaken(c, inpJson.Username)
	if err != nil {
		log.Println(err)
		resp := Response{
			Code:    1,
			Message: "Error validating username uniqueness",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}
	if isUsernameTaken {
		hasErrors = true
		registerErrors.Username = append(registerErrors.Username, "This username is already taken")
	}

	// check email is unique
	isEmailTaken, err := queries.IsEmailTaken(c, inpJson.Email)
	if err != nil {
		log.Println(err)
		resp := Response{
			Code:    1,
			Message: "Error validating email uniqueness",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}
	if isEmailTaken {
		hasErrors = true
		registerErrors.Email = append(registerErrors.Email, "This email is already taken")
	}

	// check email is unique
	isPhoneTaken, err := queries.IsPhoneTaken(c, inpJson.Phone)
	if err != nil {
		log.Println(err)
		resp := Response{
			Code:    1,
			Message: "Error validating phone uniqueness",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}
	if isPhoneTaken {
		hasErrors = true
		registerErrors.Phone = append(registerErrors.Phone, "This phone is already taken")
	}

	// check password length
	if len(inpJson.Password) < 7 {
		hasErrors = true
		registerErrors.Password = append(registerErrors.Password, "Password must have atleast 7 characters")
	}

	// check if password matches
	if inpJson.Password != inpJson.ConfirmPassword {
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
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(resp)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(inpJson.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Println(err)
		resp := Response{
			Code:    1,
			Message: "Error hashing password",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}

	err = queries.RegisterUser(c, db_sqlc.RegisterUserParams{
		Uuid:     utils.GenerateUUID(),
		Username: inpJson.Username,
		Email:    inpJson.Email,
		Phone:    inpJson.Phone,
		Password: string(hashedPassword),
	})
	if err != nil {
		log.Println(err)
		resp := Response{
			Code:    1,
			Message: "Error registering user",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}

	response := Response{
		Code:    0,
		Message: "User registered successfully",
	}

	json.NewEncoder(w).Encode(response)
}

type LoginBody struct {
	UsernameOrEmail string `json:"username_or_email"`
	Password        string `json:"password"`
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// parse json body
	var inpJson LoginBody
	err := json.NewDecoder(r.Body).Decode(&inpJson)
	if err != nil {
		log.Println(err)
		resp := Response{
			Code:    1,
			Message: "Unable to parse json body",
		}
		w.WriteHeader(http.StatusInternalServerError)
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

	if inpJson.UsernameOrEmail == "" {
		hasErrors = true
		loginErrors.UsernameOrEmail = append(loginErrors.UsernameOrEmail, "This field is required")
	}

	if inpJson.Password == "" {
		hasErrors = true
		loginErrors.Password = append(loginErrors.Password, "This field is required")
	}

	if hasErrors {
		resp := Response{
			Code:    1,
			Message: "Please correct form errors",
			Data:    loginErrors,
		}
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(resp)
		return
	}

	user, err := queries.GetDetailsForLogin(c, db_sqlc.GetDetailsForLoginParams{
		Username: inpJson.UsernameOrEmail,
		Email:    inpJson.UsernameOrEmail,
	})
	if err != nil {
		if err == sql.ErrNoRows {
			resp := Response{
				Code:    1,
				Message: "Invalid login credentials",
			}
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(resp)
			return
		}
		log.Println(err)
		resp := Response{
			Code:    1,
			Message: "Unable to validate login credentials",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(inpJson.Password))
	if err != nil {
		log.Println(err)
		resp := Response{
			Code:    1,
			Message: "Invalid login credentials",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}

	// todo: generate jwt
	accessToken, refreshToken, err := utils.CreateToken(user.Username)
	if err != nil {
		log.Println(err)
		resp := Response{
			Code:    1,
			Message: "Error Generating jwt",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}

	type SuccessData struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}

	resp := Response{
		Code:    0,
		Message: "Login successful",
		Data: SuccessData{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		},
	}
	json.NewEncoder(w).Encode(resp)
}
