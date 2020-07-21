package model

type User struct {
	ID uint64            `json:"id"`
	Username  string `json:"username"`
	FirstName string `json:"firstname"`
	LastName  string `json:"lastname"`
	Password  string `json:"password"`
	Token     string `json:"token"`
}

type ResponseResult struct {
	Error  string `json:"error"`
	Result string `json:"result"`
}

//type UserToken struct {
//	Id string                    `json:"id"`
//	AccessToken string           `json:"access"`
//	Refresh   *UserRefreshToken  `json:"refresh"`
//}

//type UserRefreshToken struct {
//	RefreshToken string           `json:"refresh"`
//}

type TokenDetails struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	//AccessUuid   string
	//RefreshUuid  string
	//AtExpires    int64
	RtExpires    int64
}