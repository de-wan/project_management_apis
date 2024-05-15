package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/de-wan/project_management_apis/db_sqlc"
	"github.com/de-wan/project_management_apis/utils"
	"golang.org/x/crypto/bcrypt"
)

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
		resp := utils.Resp{
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
		resp := utils.Resp{
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
		resp := utils.Resp{
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
		resp := utils.Resp{
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
		resp := utils.Resp{
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
		resp := utils.Resp{
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
		resp := utils.Resp{
			Code:    1,
			Message: "Error registering user",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}

	response := utils.Resp{
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
		resp := utils.Resp{
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
		resp := utils.Resp{
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
			resp := utils.Resp{
				Code:    1,
				Message: "Invalid login credentials",
			}
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(resp)
			return
		}
		log.Println(err)
		resp := utils.Resp{
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
		resp := utils.Resp{
			Code:    1,
			Message: "Invalid login credentials",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}

	// todo: generate jwt
	accessToken, refreshToken, err := utils.CreateToken(user)
	if err != nil {
		log.Println(err)
		resp := utils.Resp{
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

	resp := utils.Resp{
		Code:    0,
		Message: "Login successful",
		Data: SuccessData{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		},
	}
	json.NewEncoder(w).Encode(resp)
}

func CurrentUserHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	claims, err := utils.GetAccessTokenClaims(r)
	if err != nil {
		log.Println(err)
		resp := utils.Resp{
			Code:    1,
			Message: err.Error(),
		}
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(resp)
		return
	}

	// validate data
	c := context.Background()
	queries := db_sqlc.New(db_sqlc.DB)

	currentUser, err := queries.GetCurrentUser(c, claims["uuid"].(string))
	if err != nil {
		log.Println(err)
		resp := utils.Resp{
			Code:    1,
			Message: "Unable to retrieve user",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}

	resp := utils.Resp{
		Code:    0,
		Message: "Success",
		Data:    currentUser,
	}

	json.NewEncoder(w).Encode(resp)
}

func ListProjectsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	claims, err := utils.GetAccessTokenClaims(r)
	if err != nil {
		log.Println(err)
		resp := utils.Resp{
			Code:    1,
			Message: err.Error(),
		}
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(resp)
		return
	}

	c := context.Background()
	queries := db_sqlc.New(db_sqlc.DB)

	projects, err := queries.ListProjects(c, claims["uuid"].(string))
	if err != nil {
		log.Println(err)
		resp := utils.Resp{
			Code:    1,
			Message: "Unable to retrieve projects",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}

	resp := utils.Resp{
		Code:    0,
		Message: "Success",
		Data:    projects,
	}

	json.NewEncoder(w).Encode(resp)

}

type CreateProjectBody struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func CreateProjectsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	claims, err := utils.GetAccessTokenClaims(r)
	if err != nil {
		log.Println(err)
		resp := utils.Resp{
			Code:    1,
			Message: err.Error(),
		}
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(resp)
		return
	}

	// parse json body
	var inpJson CreateProjectBody
	err = json.NewDecoder(r.Body).Decode(&inpJson)
	if err != nil {
		log.Println(err)
		resp := utils.Resp{
			Code:    1,
			Message: "Unable to parse json body",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}

	c := context.Background()
	queries := db_sqlc.New(db_sqlc.DB)

	type CreateProjectErrors struct {
		Name        []string `json:"name"`
		Description []string `json:"description"`
	}

	hasErrors := false
	errors := CreateProjectErrors{}

	if inpJson.Name == "" {
		hasErrors = true
		errors.Name = append(errors.Name, "This field is required")
	}

	if inpJson.Description == "" {
		hasErrors = true
		errors.Description = append(errors.Description, "This field is required")
	}

	// check name is unique
	isNameTaken, err := queries.IsProjectNameTaken(c, db_sqlc.IsProjectNameTakenParams{
		Name:     inpJson.Name,
		UserUuid: claims["uuid"].(string),
	})
	if err != nil {
		log.Println(err)
		resp := utils.Resp{
			Code:    1,
			Message: "Error validating username uniqueness",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}
	if isNameTaken {
		hasErrors = true
		errors.Name = append(errors.Name, "This name is already taken")
	}

	// return errors
	if hasErrors {
		resp := utils.Resp{
			Code:    1,
			Message: "Please correct form errors",
			Data:    errors,
		}
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(resp)
		return
	}

	err = queries.CreateProject(c, db_sqlc.CreateProjectParams{
		Uuid:        utils.GenerateUUID(),
		Name:        inpJson.Name,
		Description: inpJson.Description,
		UserUuid:    claims["uuid"].(string),
	})
	if err != nil {
		log.Println(err)
		resp := utils.Resp{
			Code:    1,
			Message: "Error creating project",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}

	resp := utils.Resp{
		Code:    0,
		Message: "project task created successfully",
	}
	json.NewEncoder(w).Encode(resp)
}

type UpdateProjectBody struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func UpdateProjectsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// get uuid from url
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		log.Println(errors.New("invalid url"))
		resp := utils.Resp{
			Code:    1,
			Message: "Please specify project uuid",
		}
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(resp)
		return
	}

	projectUuid := parts[4]

	claims, err := utils.GetAccessTokenClaims(r)
	if err != nil {
		log.Println(err)
		resp := utils.Resp{
			Code:    1,
			Message: err.Error(),
		}
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(resp)
		return
	}

	// parse json body
	var inpJson UpdateProjectBody
	err = json.NewDecoder(r.Body).Decode(&inpJson)
	if err != nil {
		log.Println(err)
		resp := utils.Resp{
			Code:    1,
			Message: "Unable to parse json body",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}

	c := context.Background()
	queries := db_sqlc.New(db_sqlc.DB)

	// check project exists
	doesProjectExist, err := queries.DoesProjectExist(c, projectUuid)
	if err != nil {
		log.Println(err)
		resp := utils.Resp{
			Code:    1,
			Message: "Error checking project existance",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}
	if !doesProjectExist {
		resp := utils.Resp{
			Code:    1,
			Message: fmt.Sprintf("Project with uuid %s not found", projectUuid),
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}

	type UpdateProjectErrors struct {
		Name        []string `json:"name"`
		Description []string `json:"description"`
	}

	hasErrors := false
	errors := UpdateProjectErrors{}

	if inpJson.Name == "" {
		hasErrors = true
		errors.Name = append(errors.Name, "This field is required")
	}

	if inpJson.Description == "" {
		hasErrors = true
		errors.Description = append(errors.Description, "This field is required")
	}

	// check name is unique
	isNameTaken, err := queries.IsProjectNameTakenForProject(c, db_sqlc.IsProjectNameTakenForProjectParams{
		Name:     inpJson.Name,
		UserUuid: claims["uuid"].(string),
		Uuid:     projectUuid,
	})
	if err != nil {
		log.Println(err)
		resp := utils.Resp{
			Code:    1,
			Message: "Error validating username uniqueness",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}
	if isNameTaken {
		hasErrors = true
		errors.Name = append(errors.Name, "This name is already taken")
	}

	// return errors
	if hasErrors {
		resp := utils.Resp{
			Code:    1,
			Message: "Please correct form errors",
			Data:    errors,
		}
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(resp)
		return
	}

	err = queries.UpdateProject(c, db_sqlc.UpdateProjectParams{
		Uuid:        projectUuid,
		Name:        inpJson.Name,
		Description: inpJson.Description,
	})
	if err != nil {
		log.Println(err)
		resp := utils.Resp{
			Code:    1,
			Message: "Error updating project",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}

	resp := utils.Resp{
		Code:    0,
		Message: "project updated successfully",
	}
	json.NewEncoder(w).Encode(resp)
}

func ListArchivedProjectsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	claims, err := utils.GetAccessTokenClaims(r)
	if err != nil {
		log.Println(err)
		resp := utils.Resp{
			Code:    1,
			Message: err.Error(),
		}
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(resp)
		return
	}

	c := context.Background()
	queries := db_sqlc.New(db_sqlc.DB)

	projects, err := queries.ListArchivedProjects(c, claims["uuid"].(string))
	if err != nil {
		log.Println(err)
		resp := utils.Resp{
			Code:    1,
			Message: "Unable to retrieve archived projects",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}

	resp := utils.Resp{
		Code:    0,
		Message: "Success",
		Data:    projects,
	}

	json.NewEncoder(w).Encode(resp)

}

func ArchiveProjectsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// get uuid from url
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		log.Println(errors.New("invalid url"))
		resp := utils.Resp{
			Code:    1,
			Message: "Please specify project uuid",
		}
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(resp)
		return
	}

	projectUuid := parts[4]

	claims, err := utils.GetAccessTokenClaims(r)
	if err != nil {
		log.Println(err)
		resp := utils.Resp{
			Code:    1,
			Message: err.Error(),
		}
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(resp)
		return
	}

	c := context.Background()
	queries := db_sqlc.New(db_sqlc.DB)

	projectExists, err := queries.DoesProjectExist(c, projectUuid)
	if err != nil {
		log.Println(err)
		resp := utils.Resp{
			Code:    1,
			Message: "Error checking project exists",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}

	if !projectExists {
		log.Println(err)
		resp := utils.Resp{
			Code:    1,
			Message: fmt.Sprintf("Project with uuid: %s not found", projectUuid),
		}
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(resp)
		return
	}

	err = queries.ArchiveProject(c, db_sqlc.ArchiveProjectParams{
		Uuid:     projectUuid,
		UserUuid: claims["uuid"].(string),
	})
	if err != nil {
		log.Println(err)
		resp := utils.Resp{
			Code:    1,
			Message: "Error archiving project",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}

	resp := utils.Resp{
		Code:    0,
		Message: "project archived successfully",
	}
	json.NewEncoder(w).Encode(resp)
}

func UnArchiveProjectsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// get uuid from url
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		log.Println(errors.New("invalid url"))
		resp := utils.Resp{
			Code:    1,
			Message: "Please specify project uuid",
		}
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(resp)
		return
	}

	projectUuid := parts[4]

	claims, err := utils.GetAccessTokenClaims(r)
	if err != nil {
		log.Println(err)
		resp := utils.Resp{
			Code:    1,
			Message: err.Error(),
		}
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(resp)
		return
	}

	c := context.Background()
	queries := db_sqlc.New(db_sqlc.DB)

	archivedProject, err := queries.RetrieveArchivedProject(c, projectUuid)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Println(err)
			resp := utils.Resp{
				Code:    1,
				Message: fmt.Sprintf("Project with uuid: %s not found", projectUuid),
			}
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(resp)
			return
		}

		log.Println(err)
		resp := utils.Resp{
			Code:    1,
			Message: "Error checking project exists",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}

	if !archivedProject.ArchivedAt.Valid {
		errStr := fmt.Sprintf("Project with uuid: %s not in archive", projectUuid)
		log.Println(errStr)
		resp := utils.Resp{
			Code:    1,
			Message: errStr,
		}
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(resp)
		return
	}

	err = queries.UnarchiveProject(c, db_sqlc.UnarchiveProjectParams{
		Uuid:     projectUuid,
		UserUuid: claims["uuid"].(string),
	})
	if err != nil {
		log.Println(err)
		resp := utils.Resp{
			Code:    1,
			Message: "Error unarchiving project",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}

	resp := utils.Resp{
		Code:    0,
		Message: "project unarchived successfully",
	}
	json.NewEncoder(w).Encode(resp)
}

func ListAllProjectTasksHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	claims, err := utils.GetAccessTokenClaims(r)
	if err != nil {
		log.Println(err)
		resp := utils.Resp{
			Code:    1,
			Message: err.Error(),
		}
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(resp)
		return
	}

	c := context.Background()
	queries := db_sqlc.New(db_sqlc.DB)

	projectTasks, err := queries.ListAllProjectTasks(c, claims["uuid"].(string))
	if err != nil {
		log.Println(err)
		resp := utils.Resp{
			Code:    1,
			Message: "Unable to retrieve project tasks",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}

	resp := utils.Resp{
		Code:    0,
		Message: "Success",
		Data:    projectTasks,
	}

	json.NewEncoder(w).Encode(resp)
}

func ListProjectTasksHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	claims, err := utils.GetAccessTokenClaims(r)
	if err != nil {
		log.Println(err)
		resp := utils.Resp{
			Code:    1,
			Message: err.Error(),
		}
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(resp)
		return
	}

	// get uuid from url
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		log.Println(errors.New("invalid url"))
		resp := utils.Resp{
			Code:    1,
			Message: "Please specify project uuid",
		}
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(resp)
		return
	}

	projectUuid := parts[4]

	c := context.Background()
	queries := db_sqlc.New(db_sqlc.DB)

	projectExists, err := queries.DoesProjectExist(c, projectUuid)
	if err != nil {
		log.Println(err)
		resp := utils.Resp{
			Code:    1,
			Message: "Error checking project exists",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}

	if !projectExists {
		log.Println(err)
		resp := utils.Resp{
			Code:    1,
			Message: fmt.Sprintf("Project with uuid: %s not found", projectUuid),
		}
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(resp)
		return
	}

	projectTasks, err := queries.ListProjectTasks(c, db_sqlc.ListProjectTasksParams{
		UserUuid: claims["uuid"].(string),
		Uuid:     projectUuid,
	})
	if err != nil {
		log.Println(err)
		resp := utils.Resp{
			Code:    1,
			Message: "Unable to retrieve project tasks",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}

	resp := utils.Resp{
		Code:    0,
		Message: "Success",
		Data:    projectTasks,
	}

	json.NewEncoder(w).Encode(resp)
}

type CreateProjectTaskBody struct {
	ProjectUuid string `json:"project_uuid"`
	Name        string `json:"name"`
	Deadline    string `json:"deadline"`
}

func CreateProjectTasksHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	_, err := utils.GetAccessTokenClaims(r)
	if err != nil {
		log.Println(err)
		resp := utils.Resp{
			Code:    1,
			Message: err.Error(),
		}
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(resp)
		return
	}

	// parse json body
	var inpJson CreateProjectTaskBody
	err = json.NewDecoder(r.Body).Decode(&inpJson)
	if err != nil {
		log.Println(err)
		resp := utils.Resp{
			Code:    1,
			Message: "Unable to parse json body",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}

	c := context.Background()
	queries := db_sqlc.New(db_sqlc.DB)

	type CreateProjectTaskErrors struct {
		ProjectUuid []string `json:"project_uuid"`
		Name        []string `json:"name"`
		Deadline    []string `json:"deadline"`
	}

	hasErrors := false
	errors := CreateProjectTaskErrors{}

	if inpJson.ProjectUuid == "" {
		hasErrors = true
		errors.ProjectUuid = append(errors.ProjectUuid, "This field is required")
	}

	if inpJson.Name == "" {
		hasErrors = true
		errors.Name = append(errors.Name, "This field is required")
	}

	if inpJson.Deadline == "" {
		hasErrors = true
		errors.Deadline = append(errors.Deadline, "This field is required")
	}

	// check project exists
	doesProjectExist, err := queries.DoesProjectExist(c, inpJson.ProjectUuid)
	if err != nil {
		log.Println(err)
		resp := utils.Resp{
			Code:    1,
			Message: "Error checking project existance",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}
	if !doesProjectExist {
		hasErrors = true
		errors.Name = append(errors.Name, fmt.Sprintf("Project with uuid %s not found", inpJson.ProjectUuid))
	}

	// check name is unique
	isNameTaken, err := queries.IsProjectTaskNameTaken(c, db_sqlc.IsProjectTaskNameTakenParams{
		Name:        inpJson.Name,
		ProjectUuid: inpJson.ProjectUuid,
	})
	if err != nil {
		log.Println(err)
		resp := utils.Resp{
			Code:    1,
			Message: "Error validating name uniqueness",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}
	if isNameTaken {
		hasErrors = true
		errors.Name = append(errors.Name, "This name is already taken")
	}

	// parse deadline
	var parsedDeadline time.Time
	if inpJson.Deadline != "" {
		parsedDeadline, err = time.Parse("2006-01-15", inpJson.Deadline)
		if err != nil {
			log.Println(err)
			hasErrors = true
			errors.Deadline = append(errors.Deadline, "Unable to parse deadline. Please use yyyy-MM-dd")
		}
	}

	// return errors
	if hasErrors {
		resp := utils.Resp{
			Code:    1,
			Message: "Please correct form errors",
			Data:    errors,
		}
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(resp)
		return
	}

	err = queries.CreateProjectTask(c, db_sqlc.CreateProjectTaskParams{
		Uuid:        utils.GenerateUUID(),
		Name:        inpJson.Name,
		Deadline:    parsedDeadline,
		ProjectUuid: inpJson.ProjectUuid,
	})
	if err != nil {
		log.Println(err)
		resp := utils.Resp{
			Code:    1,
			Message: "Error creating project task",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}

	resp := utils.Resp{
		Code:    0,
		Message: "project task created successfully",
	}
	json.NewEncoder(w).Encode(resp)

}

type UpdateProjectTaskBody struct {
	Name     string `json:"name"`
	Deadline string `json:"deadline"`
}

func UpdateProjectTasksHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// get uuid from url
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		log.Println(errors.New("invalid url"))
		resp := utils.Resp{
			Code:    1,
			Message: "Please specify project uuid",
		}
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(resp)
		return
	}

	projectTaskUuid := parts[4]

	claims, err := utils.GetAccessTokenClaims(r)
	if err != nil {
		log.Println(err)
		resp := utils.Resp{
			Code:    1,
			Message: err.Error(),
		}
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(resp)
		return
	}

	// parse json body
	var inpJson UpdateProjectTaskBody
	err = json.NewDecoder(r.Body).Decode(&inpJson)
	if err != nil {
		log.Println(err)
		resp := utils.Resp{
			Code:    1,
			Message: "Unable to parse json body",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}

	c := context.Background()
	queries := db_sqlc.New(db_sqlc.DB)

	// check project task exists
	doesProjectExist, err := queries.DoesProjectTaskExist(c, db_sqlc.DoesProjectTaskExistParams{
		Uuid:     projectTaskUuid,
		UserUuid: claims["uuid"].(string),
	})
	if err != nil {
		log.Println(err)
		resp := utils.Resp{
			Code:    1,
			Message: "Error checking project existance",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}
	if !doesProjectExist {
		resp := utils.Resp{
			Code:    1,
			Message: fmt.Sprintf("Project task with uuid %s not found", projectTaskUuid),
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}

	type UpdateProjectTaskErrors struct {
		Name     []string `json:"name"`
		Deadline []string `json:"deadline"`
	}

	hasErrors := false
	errors := UpdateProjectTaskErrors{}

	if inpJson.Name == "" {
		hasErrors = true
		errors.Name = append(errors.Name, "This field is required")
	}

	if inpJson.Deadline == "" {
		hasErrors = true
		errors.Deadline = append(errors.Deadline, "This field is required")
	}

	// check name is unique
	isNameTaken, err := queries.IsProjectTaskNameTakenForProjectTask(c, db_sqlc.IsProjectTaskNameTakenForProjectTaskParams{
		Name: inpJson.Name,
		Uuid: projectTaskUuid,
	})
	if err != nil {
		log.Println(err)
		resp := utils.Resp{
			Code:    1,
			Message: "Error validating name uniqueness",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}
	if isNameTaken {
		hasErrors = true
		errors.Name = append(errors.Name, "This name is already taken")
	}

	// parse deadline
	var parsedDeadline time.Time
	if inpJson.Deadline != "" {
		parsedDeadline, err = time.Parse("2006-01-15", inpJson.Deadline)
		if err != nil {
			log.Println(err)
			hasErrors = true
			errors.Deadline = append(errors.Deadline, "Unable to parse deadline. Please use yyyy-MM-dd")
		}
	}

	// return errors
	if hasErrors {
		resp := utils.Resp{
			Code:    1,
			Message: "Please correct form errors",
			Data:    errors,
		}
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(resp)
		return
	}

	err = queries.UpdateProjectTask(c, db_sqlc.UpdateProjectTaskParams{
		Uuid:     projectTaskUuid,
		Name:     inpJson.Name,
		Deadline: parsedDeadline,
	})
	if err != nil {
		log.Println(err)
		resp := utils.Resp{
			Code:    1,
			Message: "Error updating project task",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}

	resp := utils.Resp{
		Code:    0,
		Message: "project task updated successfully",
	}
	json.NewEncoder(w).Encode(resp)
}

func ListArchivedProjectTasksHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	claims, err := utils.GetAccessTokenClaims(r)
	if err != nil {
		log.Println(err)
		resp := utils.Resp{
			Code:    1,
			Message: err.Error(),
		}
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(resp)
		return
	}

	// get uuid from url
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		log.Println(errors.New("invalid url"))
		resp := utils.Resp{
			Code:    1,
			Message: "Please specify project uuid",
		}
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(resp)
		return
	}

	projectUuid := parts[4]

	c := context.Background()
	queries := db_sqlc.New(db_sqlc.DB)

	projectExists, err := queries.DoesProjectExist(c, projectUuid)
	if err != nil {
		log.Println(err)
		resp := utils.Resp{
			Code:    1,
			Message: "Error checking project exists",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}

	if !projectExists {
		log.Println(err)
		resp := utils.Resp{
			Code:    1,
			Message: fmt.Sprintf("Project with uuid: %s not found", projectUuid),
		}
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(resp)
		return
	}

	projectTasks, err := queries.ListArchivedProjectTasks(c, db_sqlc.ListArchivedProjectTasksParams{
		UserUuid: claims["uuid"].(string),
		Uuid:     projectUuid,
	})
	if err != nil {
		log.Println(err)
		resp := utils.Resp{
			Code:    1,
			Message: "Unable to retrieve project tasks",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}

	resp := utils.Resp{
		Code:    0,
		Message: "Success",
		Data:    projectTasks,
	}

	json.NewEncoder(w).Encode(resp)
}

func ArchiveProjectTaskHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// get uuid from url
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		log.Println(errors.New("invalid url"))
		resp := utils.Resp{
			Code:    1,
			Message: "Please specify project task uuid",
		}
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(resp)
		return
	}

	projectTaskUuid := parts[4]

	claims, err := utils.GetAccessTokenClaims(r)
	if err != nil {
		log.Println(err)
		resp := utils.Resp{
			Code:    1,
			Message: err.Error(),
		}
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(resp)
		return
	}

	c := context.Background()
	queries := db_sqlc.New(db_sqlc.DB)

	projectTaskExists, err := queries.DoesProjectTaskExist(c, db_sqlc.DoesProjectTaskExistParams{
		Uuid:     projectTaskUuid,
		UserUuid: claims["uuid"].(string),
	})
	if err != nil {
		log.Println(err)
		resp := utils.Resp{
			Code:    1,
			Message: "Error checking project exists",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}

	if !projectTaskExists {
		log.Println(err)
		resp := utils.Resp{
			Code:    1,
			Message: fmt.Sprintf("Project task with uuid: %s not found", projectTaskUuid),
		}
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(resp)
		return
	}

	err = queries.ArchiveProjectTask(c, projectTaskUuid)
	if err != nil {
		log.Println(err)
		resp := utils.Resp{
			Code:    1,
			Message: "Error archiving project task",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}

	resp := utils.Resp{
		Code:    0,
		Message: "project task archived successfully",
	}
	json.NewEncoder(w).Encode(resp)
}

func UnArchiveProjectTaskHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// get uuid from url
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		log.Println(errors.New("invalid url"))
		resp := utils.Resp{
			Code:    1,
			Message: "Please specify project task uuid",
		}
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(resp)
		return
	}

	projectTaskUuid := parts[4]

	_, err := utils.GetAccessTokenClaims(r)
	if err != nil {
		log.Println(err)
		resp := utils.Resp{
			Code:    1,
			Message: err.Error(),
		}
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(resp)
		return
	}

	c := context.Background()
	queries := db_sqlc.New(db_sqlc.DB)

	archivedProjectTask, err := queries.RetrieveArchivedProjectTask(c, projectTaskUuid)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Println(err)
			resp := utils.Resp{
				Code:    1,
				Message: fmt.Sprintf("Project task with uuid: %s not found", projectTaskUuid),
			}
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(resp)
			return
		}

		log.Println(err)
		resp := utils.Resp{
			Code:    1,
			Message: "Error checking project task exists",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}

	if !archivedProjectTask.ArchivedAt.Valid {
		errStr := fmt.Sprintf("Project task with uuid: %s not in archive", projectTaskUuid)
		log.Println(errStr)
		resp := utils.Resp{
			Code:    1,
			Message: errStr,
		}
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(resp)
		return
	}

	err = queries.UnarchiveProjectTask(c, projectTaskUuid)
	if err != nil {
		log.Println(err)
		resp := utils.Resp{
			Code:    1,
			Message: "Error unarchiving project",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}

	resp := utils.Resp{
		Code:    0,
		Message: "project task unarchived successfully",
	}
	json.NewEncoder(w).Encode(resp)
}
