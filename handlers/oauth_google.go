package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var googleOauthConfig = &oauth2.Config{
	RedirectURL:  "http://localhost:9001/auth/google/callback",
	ClientID:     "GCP client ID",
	ClientSecret: "GCP client Secret",
	Scopes: []string{
		"https://www.googleapis.com/auth/userinfo.email",
		"https://www.googleapis.com/auth/userinfo.profile"},
	Endpoint: google.Endpoint,
}

const oauthGoogleUrlAPI = "https://www.googleapis.com/oauth2/v2/userinfo?access_token="

func oauthGoogleLogin(w http.ResponseWriter, r *http.Request) {
	// 쿠키를 생성하여 클라이언(브라우저)의 정보를 불러온다.
	oauthState := generateStateOauthCookie(w)

	// 사용자권한을 명시적으로 요청하는 OAuth2.0 provider의 허가 페이지 url을 반환한다.
	// state값은 csrf 공격으로부터 사용자를 보호하기 위한 토큰이다.
	// 항상 비어있지 않은 문자열을 제공하고
	//redirect callback의 상태쿼리의 파라미터와 일치하는지 확인해야한다.
	u := googleOauthConfig.AuthCodeURL(oauthState)
	http.Redirect(w, r, u, http.StatusTemporaryRedirect)
}

func generateStateOauthCookie(w http.ResponseWriter) string {
	// 쿠키
	// 사용자가 방문한 웹페이지에서 이용된 환경설정 및 기타정보를 사용자의 컴퓨터에 저장하는 작은 파일.
	// 클라이언트(브라우저) 로컬에 저장되는 키와 값이 들어있는 작은 데이터 파일.
	// 클라이언트의 상태 정보를 로컬에 저장했다가 참조한다.
	// 사용자가 따로 요청하지 않아도 브라우저가 request시에 request header를 넣어서 자동으로 서버에 전송.

	// 쿠키의 구성요소
	// 1) 이름: 쿠키를 구별하는데 사용되는 이름
	// 2) 값: 쿠키의 이름과 관련된 값
	// 3) 유효시간: 쿠키의 유지시간
	// 4) 도메인: 쿠키를 전송할 도메인
	// 5) 경로: 쿠키를 전송할 요청 경로

	// 쿠키 유효시간: 20분
	var expiration = time.Now().Add(20 * time.Minute)

	b := make([]byte, 16)
	rand.Read(b)

	// 16byte 랜덤값을 생성하여, base64 인코딩을하여 상태정보값을 생성.
	// request header에 넣어서 자동으로 서버 전송하기위해서 함.
	state := base64.URLEncoding.EncodeToString(b)
	cookie := http.Cookie{Name: "oauthstate", Value: state, Expires: expiration}
	http.SetCookie(w, &cookie)
	return state
}

func getUserDataFromGoogle(code string) ([]byte, error) {
	// Exchange()
	// authorization-code를 토큰으로 변환시킨다.
	token, err := googleOauthConfig.Exchange(context.Background(), code)
	if err != nil {
		return nil, fmt.Errorf("code exchange wrong : %s", err.Error())
	}

	response, err := http.Get(oauthGoogleUrlAPI + token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed getting user info: %s", err.Error())
	}

	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed read response : %s", err.Error())
	}
	return contents, nil
}

// oauth2.0 인증을 한 뒤에 돌아간다.
func oauthGoogleCallback(w http.ResponseWriter, r *http.Request) {
	oauthState, _ := r.Cookie("oauthstate")

	// 컴포넌트에 매핑된, 입력폼으로부터의 매핑된 값을 불러온다.
	if r.FormValue("state") != oauthState.Value {
		log.Println("invalid oauth google state")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	data, err := getUserDataFromGoogle(r.FormValue("code"))
	if err != nil {
		log.Println(err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	fmt.Fprintf(w, "UserInfo : %s\n", data)
}
