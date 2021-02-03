package jwt

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"strconv"
	"time"
)

type CustomClaims struct {
	Uid int64 `json:"uid"`
	jwt.StandardClaims
}

func CreateToken(uid int64, key string, expires int64) (string, error) {
	stringUid := strconv.FormatInt(uid, 10)
	claims := CustomClaims{
		uid,
		jwt.StandardClaims{
			Id:        stringUid,
			Subject:   key,
			Audience:  key,
			ExpiresAt: time.Now().Unix() + expires,
			Issuer:    "",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString([]byte(key))
	//tokenStr, err := token.SignedString([]byte("946356eb-204d-4be3-8eb0-32720a403814"))
	if err != nil {
		return "", errors.New(fmt.Sprintf(`create token err:%v`, err))
	}
	return tokenStr, err
}

func VerifyToken(tokenString, key string) (uid int64, err error) {
	tokenValue, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(key), nil
	})
	if err != nil {
		err = errors.New(err.Error())
		return
	}
	claims, ok := tokenValue.Claims.(*CustomClaims)
	if !ok {
		err = errors.New("Token is invalid")
		return
	}
	uid = claims.Uid
	return
}

func GetUid(c *gin.Context) int {
	if val, ex := c.Get("uid"); ex {
		return int(val.(int64))
	}
	return 0
}
