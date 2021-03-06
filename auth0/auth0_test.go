package auth0

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/integralist/go-findroot/find"
	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/suite"
)

type testTokenConfig struct {
	Invalid  string `envconfig:"TEST_TOKEN_INVALID"`
	MultiAud string `envconfig:"TEST_TOKEN_MULTIPLE_AUDIENCE"`
	Expired  string `envconfig:"TEST_TOKEN_EXPIRED"`
}

var testConfig Config
var testTokens testTokenConfig

// ---- START: Initialize Test Environment
func init() {
	testConfig, _ = LoadTestConfig()
	testTokens, _ = LoadTestTokens()
}

// ---- END: Initialize Test Environment

// ---- START: SETUP UNIT TEST SUITE
type UnitTestSuite struct {
	suite.Suite
}

func TestUnitTestSuite(t *testing.T) {
	suite.Run(t, new(UnitTestSuite))

}

// ---- END: SETUP UNIT TEST SUITE

func (suite *UnitTestSuite) TestGetManagementAPIToken() {
	a0 := New(&testConfig)
	tResp, err := a0.GetManagementAPIToken()
	suite.Nil(err, "Error not Nil")
	suite.Greater(len(tResp.Raw), 0)
	suite.True(tResp.Valid)

	// Second time to test cached token
	tResp2, err := a0.GetManagementAPIToken()
	suite.Nil(err, "Error not Nil")
	suite.Equal(tResp.Raw, tResp2.Raw, "Tokens don't match!")
}

func (suite *UnitTestSuite) TestGetApplicationAPIToken() {
	a0 := New(&testConfig)
	tResp, err := a0.GetApplicationAPIToken()
	suite.Nil(err, "Error not Nil")
	suite.Greater(len(tResp.Raw), 0)
	suite.True(tResp.Valid)

	// Second time to test cached token
	tResp2, err := a0.GetApplicationAPIToken()
	suite.Nil(err, "Error not Nil")
	suite.Equal(tResp.Raw, tResp2.Raw, "Tokens don't match!")

	// Clear the cache
	a0.ClearCachedTokens()

	// Third time to test cleared cache
	tResp3, err := a0.GetApplicationAPIToken()
	suite.Nil(err, "Error not Nil")
	suite.NotEqual(tResp.Raw, tResp3.Raw, "Tokens shouldn't match!")
}

func (suite *UnitTestSuite) TestMiddleware() {
	a0 := New(&testConfig)
	tResp, err := a0.GetApplicationAPIToken()
	suite.Nil(err, "Error not Nil")
	suite.Greater(len(tResp.Raw), 0)

	// 1. Setup the REQUEST / response
	httpReq, _ := http.NewRequest("GET", "/", nil)
	httpReq.Header.Set("Authorization", "Bearer "+tResp.Raw)
	var respWriter http.ResponseWriter

	// Init the middleware:
	a0Middleware := a0.NewMiddleware()
	err = a0Middleware.CheckJWT(respWriter, httpReq)
	suite.Nil(err, "Error not Nil")

}

func (suite *UnitTestSuite) TestInvalidToken() {
	var err error
	token := testTokens.Invalid
	a0 := New(&testConfig)

	// 1. Setup the REQUEST / response
	httpReq := httptest.NewRequest("GET", "/", nil)
	httpReq.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()

	// Init the middleware:
	a0Middleware := a0.NewMiddleware()
	err = a0Middleware.CheckJWT(recorder, httpReq)
	suite.Equal("Error parsing token: unexpected end of JSON input", err.Error(), "Unexpected Error")
}

func (suite *UnitTestSuite) TestMiddlewareMultiAudience() {

	var err error
	token := testTokens.MultiAud
	a0 := New(&testConfig)

	// 1. Setup the REQUEST / response
	httpReq := httptest.NewRequest("GET", "/", nil)
	httpReq.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()

	// Init the middleware:
	a0Middleware := a0.NewMiddleware()
	err = a0Middleware.CheckJWT(recorder, httpReq)
	suite.Nil(err, "Error not Nil")
}

func (suite *UnitTestSuite) TestMiddlewareTokenExpired() {
	var err error
	token := testTokens.Expired
	a0 := New(&testConfig)

	// 1. Setup the REQUEST / response
	httpReq := httptest.NewRequest("GET", "/", nil)
	httpReq.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()

	// Init the middleware:
	a0Middleware := a0.NewMiddleware()
	err = a0Middleware.CheckJWT(recorder, httpReq)
	suite.Equal("Error parsing token: Token is expired", err.Error(), "Unexpected Error")
}

// ---- SUPPORTING FUNCTIONS

func LoadTestConfig() (Config, error) {

	_ = godotenv.Load(GitRootDir() + "/.env")

	cfg := Config{}
	err := envconfig.Process("", &cfg)

	return cfg, err

}

func LoadTestTokens() (testTokenConfig, error) {

	_ = godotenv.Load(GitRootDir() + "/.env")

	cfg := testTokenConfig{}
	err := envconfig.Process("", &cfg)

	return cfg, err

}

func GitRootDir() string {
	root, err := find.Repo()
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Errorln("Error finding Root with Git")
		return ""
	}
	return root.Path
}
