package jwt_package

type TokenDetails struct {
	AccessToken  string
	RefreshToken string
	AtExpires    int64
	RtExpires    int64
}

type UserIdInt struct {
	UserId int64
}

type UserIdString struct {
	UserId string
}

type IntUserInformation struct {
	UserId    int64
	UserEmail string
}

type StringUserInformation struct {
	UserId    string
	UserEmail string
}

type CustomToken struct {
	CustomDetails map[string]string
}
