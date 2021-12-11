package jwt_package

import (
	"github.com/dgrijalva/jwt-go"
	"os"
	"strconv"
	"time"
)

type TokenClaim interface {
	GetToken() TokenDetails
}

func (userinfo UserIdInt) GetToken() (*TokenDetails, error) {
	td := &TokenDetails{}
	accessSecret := os.Getenv("JWT_ACCESS_SECRET")
	refreshSecret := os.Getenv("JWT_REFRESH_SECRET")
	tokenExpireTime, _ := strconv.Atoi(os.Getenv("TOKEN_EXPIRE_AT"))
	refreshExpireTime, _ := strconv.Atoi(os.Getenv("REFRESH_TOKEN_EXPIRE_AT"))

	td.AtExpires = time.Now().Add(time.Duration(tokenExpireTime) * time.Second).Unix()
	td.RtExpires = time.Now().Add(time.Duration(refreshExpireTime) * time.Second).Unix()
	var err error
	//Creating Access Token
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["user_id"] = userinfo.UserId
	atClaims["expire_at"] = td.AtExpires
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	td.AccessToken, err = at.SignedString([]byte(accessSecret))
	if err != nil {
		return nil, err
	}
	//Creating Refresh Token
	rtClaims := jwt.MapClaims{}
	rtClaims["user_id"] = userinfo.UserId
	rtClaims["expire_at"] = td.RtExpires
	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)
	td.RefreshToken, err = rt.SignedString([]byte(refreshSecret))
	if err != nil {
		return nil, err
	}
	return td, nil
}

func (userinfo UserIdString) GetToken() (*TokenDetails, error) {
	td := &TokenDetails{}
	accessSecret := os.Getenv("JWT_ACCESS_SECRET")
	refreshSecret := os.Getenv("JWT_REFRESH_SECRET")
	tokenExpireTime, _ := strconv.Atoi(os.Getenv("TOKEN_EXPIRE_AT"))
	refreshExpireTime, _ := strconv.Atoi(os.Getenv("REFRESH_TOKEN_EXPIRE_AT"))

	td.AtExpires = time.Now().Add(time.Duration(tokenExpireTime) * time.Second).Unix()
	td.RtExpires = time.Now().Add(time.Duration(refreshExpireTime) * time.Second).Unix()
	var err error
	//Creating Access Token
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["user_id"] = userinfo.UserId
	atClaims["expire_at"] = td.AtExpires
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	td.AccessToken, err = at.SignedString([]byte(accessSecret))
	if err != nil {
		return nil, err
	}
	//Creating Refresh Token
	rtClaims := jwt.MapClaims{}
	rtClaims["user_id"] = userinfo.UserId
	rtClaims["expire_at"] = td.RtExpires
	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)
	td.RefreshToken, err = rt.SignedString([]byte(refreshSecret))
	if err != nil {
		return nil, err
	}
	return td, nil
}

func (userinfo IntUserInformation) GetToken() (*TokenDetails, error) {
	td := &TokenDetails{}
	accessSecret := os.Getenv("JWT_ACCESS_SECRET")
	refreshSecret := os.Getenv("JWT_REFRESH_SECRET")
	tokenExpireTime, _ := strconv.Atoi(os.Getenv("TOKEN_EXPIRE_AT"))
	refreshExpireTime, _ := strconv.Atoi(os.Getenv("REFRESH_TOKEN_EXPIRE_AT"))

	td.AtExpires = time.Now().Add(time.Duration(tokenExpireTime) * time.Second).Unix()
	td.RtExpires = time.Now().Add(time.Duration(refreshExpireTime) * time.Second).Unix()
	var err error
	//Creating Access Token
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["user_id"] = userinfo.UserId
	atClaims["email"] = userinfo.UserEmail
	atClaims["expire_at"] = td.AtExpires
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	td.AccessToken, err = at.SignedString([]byte(accessSecret))
	if err != nil {
		return nil, err
	}
	//Creating Refresh Token
	rtClaims := jwt.MapClaims{}
	rtClaims["user_id"] = userinfo.UserId
	rtClaims["email"] = userinfo.UserEmail
	rtClaims["expire_at"] = td.RtExpires
	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)
	td.RefreshToken, err = rt.SignedString([]byte(refreshSecret))
	if err != nil {
		return nil, err
	}
	return td, nil
}

func (userinfo StringUserInformation) GetToken() (*TokenDetails, error) {
	td := &TokenDetails{}
	accessSecret := os.Getenv("JWT_ACCESS_SECRET")
	refreshSecret := os.Getenv("JWT_REFRESH_SECRET")
	tokenExpireTime, _ := strconv.Atoi(os.Getenv("TOKEN_EXPIRE_AT"))
	refreshExpireTime, _ := strconv.Atoi(os.Getenv("REFRESH_TOKEN_EXPIRE_AT"))

	td.AtExpires = time.Now().Add(time.Duration(tokenExpireTime) * time.Second).Unix()
	td.RtExpires = time.Now().Add(time.Duration(refreshExpireTime) * time.Second).Unix()
	var err error
	//Creating Access Token
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["user_id"] = userinfo.UserId
	atClaims["email"] = userinfo.UserEmail
	atClaims["expire_at"] = td.AtExpires
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	td.AccessToken, err = at.SignedString([]byte(accessSecret))
	if err != nil {
		return nil, err
	}
	//Creating Refresh Token
	rtClaims := jwt.MapClaims{}
	rtClaims["user_id"] = userinfo.UserId
	rtClaims["email"] = userinfo.UserEmail
	rtClaims["expire_at"] = td.RtExpires
	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)
	td.RefreshToken, err = rt.SignedString([]byte(refreshSecret))
	if err != nil {
		return nil, err
	}
	return td, nil
}

func (customInfo CustomToken) GetToken() (*TokenDetails, error) {
	td := &TokenDetails{}
	accessSecret := os.Getenv("JWT_ACCESS_SECRET")
	refreshSecret := os.Getenv("JWT_REFRESH_SECRET")
	tokenExpireTime, _ := strconv.Atoi(os.Getenv("TOKEN_EXPIRE_AT"))
	refreshExpireTime, _ := strconv.Atoi(os.Getenv("REFRESH_TOKEN_EXPIRE_AT"))

	td.AtExpires = time.Now().Add(time.Duration(tokenExpireTime) * time.Second).Unix()
	td.RtExpires = time.Now().Add(time.Duration(refreshExpireTime) * time.Second).Unix()
	var err error
	//Creating Access Token
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	for key, value := range customInfo.CustomDetails {
		atClaims[key] = value
	}
	atClaims["expire_at"] = td.AtExpires
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	td.AccessToken, err = at.SignedString([]byte(accessSecret))
	if err != nil {
		return nil, err
	}
	//Creating Refresh Token
	rtClaims := jwt.MapClaims{}
	for key, value := range customInfo.CustomDetails {
		rtClaims[key] = value
	}
	rtClaims["expire_at"] = td.RtExpires
	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)
	td.RefreshToken, err = rt.SignedString([]byte(refreshSecret))
	if err != nil {
		return nil, err
	}
	return td, nil
}
