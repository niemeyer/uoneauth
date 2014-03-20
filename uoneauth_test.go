package uoneauth_test

import (
	"testing"
	"os"

	. "launchpad.net/gocheck"

	"gopkg.in/v0/qml"
	"gopkg.in/v0/qml/uoneauth"
)

func Test(t *testing.T) { TestingT(t) }

var _ = Suite(&S{})

type S struct{}

func (s *S) SetUpSuite(c *C) {
	if os.Getenv("TEST_UONEAUTH") != "1" {
		c.Skip("TEST_UONEAUTH != 1")
	}

	qml.Init(nil)
}

func (s *S) SetUpTest(c *C) {
	qml.SetLogger(c)
}

func (s *S) TestToken(c *C) {
	engine := qml.NewEngine()
	service := uoneauth.NewService(engine)

	token, err := service.Token()
	c.Assert(err, IsNil)
	hsign := token.HeaderSignature("GET", "http://example.com")
	qsign := token.QuerySignature("GET", "http://example.com")

	c.Assert(hsign, Matches, "OAuth .*, oauth_signature=.*")
	c.Assert(qsign, Matches, ".*&oauth_signature=.*")
}
