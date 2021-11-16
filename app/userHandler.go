package app

import (
	"banking-auth/dto"
	"banking-auth/service"
	"encoding/json"
	"encoding/xml"
	"github.com/barnettt/banking-lib/exceptions"
	"github.com/barnettt/banking-lib/logger"
	"net/http"
)

type UserHandler struct {
	userService service.DefaultAuthService
}

func (userHandler *UserHandler) GetUserByUserName(writer http.ResponseWriter, request *http.Request) {

	contType := request.Header.Get("Content-Type")
	var contentType bool
	if contType == contentTypeXml {
		contentType = true
	}

	userReq, err := getUserRequest(request, contentType)
	if err != nil {
		appErr := exceptions.NewPayloadParseError(err.Error())
		returnResponse(writer, appErr, contentType,
			dto.LoginResponse{})
	}
	response, anErr := userHandler.userService.GetUserByUserName(*userReq)
	if anErr != nil {
		returnResponse(writer, anErr, contentType,
			dto.LoginResponse{})
		return
	}
	returnResponse(writer, nil, contentType, *response)
}

func (userHandler *UserHandler) VerifyRequest(writer http.ResponseWriter, request *http.Request) {
	urlParams := make(map[string]string)
	contentType := request.Header.Get("Content-Type")
	// convert from query to map type
	for k := range request.URL.Query() {
		request.URL.Query().Get(k)
		urlParams[k] = request.URL.Query().Get(k)
	}
	// find the token string and call the service to authorise
	if urlParams["token"] != "" {
		isAuthorised, appErr := userHandler.userService.Verify(urlParams)
		if appErr != nil {
			writeResponse(writer, http.StatusForbidden, appErr, contentType)
			return
		} else {
			if isAuthorised {
				writeResponse(writer, http.StatusOK, isAuthorised, contentType)
				return
			} else {
				writeResponse(writer, http.StatusUnauthorized, isAuthorised, contentType)
				return
			}
		}
	} else {
		writeResponse(writer, http.StatusForbidden, exceptions.NewJwtError("missing jwt token"), contentType)
	}

}

func (userHandler *UserHandler) Refresh(writer http.ResponseWriter, request *http.Request) {
	contType := request.Header.Get("Content-Type")
	var contentType bool
	if contType == contentTypeXml {
		contentType = true
	}

	refreshReq, err := getRefreshTokenRequest(request, contentType)
	if err != nil {
		appErr := exceptions.NewPayloadParseError(err.Error())
		returnResponse(writer, appErr, contentType,
			dto.LoginResponse{})
	}
	response, anErr := userHandler.userService.RefreshToken(*refreshReq)
	if anErr != nil {
		returnResponse(writer, anErr, contentType,
			dto.LoginResponse{})
		return
	}
	returnResponse(writer, nil, contentType, *response)
}

func getUserRequest(request *http.Request, contentType bool) (*dto.UserRequest, error) {
	var userRequest *dto.UserRequest
	var err error
	if contentType {

		err = xml.NewDecoder(request.Body).Decode(&userRequest)
		if err != nil {
			logger.Error(err.Error())
			return nil, err
		}
	} else {
		err = json.NewDecoder(request.Body).Decode(&userRequest)
		if err != nil {
			logger.Error(err.Error())
			return nil, err
		}
	}

	return userRequest, err
}

func getRefreshTokenRequest(request *http.Request, contentType bool) (*dto.RefreshTokenRequest, error) {
	var refreshRequest *dto.RefreshTokenRequest
	var err error
	if contentType {

		err = xml.NewDecoder(request.Body).Decode(&refreshRequest)
		if err != nil {
			logger.Error(err.Error())
			return nil, err
		}
	} else {
		err = json.NewDecoder(request.Body).Decode(&refreshRequest)
		if err != nil {
			logger.Error(err.Error())
			return nil, err
		}
	}

	return refreshRequest, err
}

func returnResponse(writer http.ResponseWriter, error *exceptions.AppError, contentType bool, userResponse dto.LoginResponse) {
	if error != nil {
		if contentType {
			writeResponse(writer, error.Code, error.AsMessage(), contentTypeXml)
		} else {
			writeResponse(writer, error.Code, error.AsMessage(), contentTypeJson)
		}
		return
	}
	if contentType {
		// set xml content type on the writer
		writeResponse(writer, http.StatusOK, userResponse, contentTypeXml)
	} else {
		// encode the customers in json format
		writeResponse(writer, http.StatusOK, userResponse, contentTypeJson)
	}
}

func writeResponse(writer http.ResponseWriter, code int, data interface{}, contentType string) {
	writer.Header().Add("Content-Type", contentType)
	writer.WriteHeader(code)
	if contentType == contentTypeXml {
		err := xml.NewEncoder(writer).Encode(data)
		if err != nil {
			panic(err)
		}
		return
	}
	err := json.NewEncoder(writer).Encode(data)
	if err != nil {
		panic(err)
	}
}
