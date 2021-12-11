package main

import (
	"fmt"
	"github.com/hassanmdsifat/go-jwt.git"
	"os"
)

type UserInfo struct {
	name     string
	username string
	password string
}

func main() {
	os.Setenv("ACCESS_SECRET", "TESTING")
	os.Setenv("REFRESH_SECRET", "TESTING 2")
	os.Setenv("TOKEN_EXPIRE_AT", "300")           // in second
	os.Setenv("REFRESH_TOKEN_EXPIRE_AT", "86400") // in second

	userInfo := jwt_package.StringUserInformation{
		UserId:    "abcde",
		UserEmail: "hassansifat@yopmail.com",
	}
	tokenDetails, _ := userInfo.GetToken()
	fmt.Println(tokenDetails.AccessToken)
	fmt.Println(tokenDetails.RefreshToken)

	customUserInfo := make(map[string]string)
	customUserInfo["username"] = "sifat_hassan"
	customUserInfo["email"] = "hassansifat97@gmail.com"
	customToken := jwt_package.CustomToken{
		CustomDetails: customUserInfo,
	}
	customTokenDetails, _ := customToken.GetToken()

	fmt.Println(customTokenDetails.AccessToken)
	fmt.Println(customTokenDetails.RefreshToken)
}
