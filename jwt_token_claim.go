package jwt_package

func GetUserToken(t TokenClaim) TokenDetails {
	return t.GetToken()
}
