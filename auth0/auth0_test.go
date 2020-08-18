package auth0

import (
	"net/http"
	"testing"

	"github.com/integralist/go-findroot/find"
	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/suite"
)

var testConfig Config

// ---- START: Initialize Test Environment
func init() {
	testConfig, _ = LoadTestConfig()
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

func (suite *UnitTestSuite) TestGetToken() {
	a0 := New(&testConfig)
	tResp, err := a0.GetToken()
	suite.Nil(err, "Error not Nil")
	suite.Greater(len(tResp.AccessToken), 0)
}
func (suite *UnitTestSuite) TestMiddleware() {
	a0 := New(&testConfig)
	tResp, err := a0.GetToken()
	suite.Nil(err, "Error not Nil")
	suite.Greater(len(tResp.AccessToken), 0)

	// 1. Setup the REQUEST / response
	httpReq, _ := http.NewRequest("GET", "/", nil)
	httpReq.Header.Set("Authorization", "Bearer "+tResp.AccessToken)
	var respWriter http.ResponseWriter

	// Init the middleware:
	a0Middleware := a0.NewMiddleware()
	err = a0Middleware.CheckJWT(respWriter, httpReq)
	suite.Nil(err, "Error not Nil")

}

func (suite *UnitTestSuite) TestMiddlewareMultiAudience() {
	var err error
	tokenMultipleAudience := `ADDME`
	a0 := New(&testConfig)

	// 1. Setup the REQUEST / response
	httpReq, _ := http.NewRequest("GET", "/", nil)
	httpReq.Header.Set("Authorization", "Bearer "+tokenMultipleAudience)
	var respWriter http.ResponseWriter

	// Init the middleware:
	a0Middleware := a0.NewMiddleware()
	err = a0Middleware.CheckJWT(respWriter, httpReq)
	suite.Nil(err, "Error not Nil")
}

// ---- SUPPORTING FUNCTIONS

func LoadTestConfig() (Config, error) {

	_ = godotenv.Load(GitRootDir() + "/.env")

	cfg := Config{}
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
