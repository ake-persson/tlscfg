package tlscfg

import (
	"crypto/tls"
	"errors"
	"os"
	"os/exec"
)

func appendSystemCerts(c *tls.Config) error {
	var homedir string = os.Getenv("HOME")
	if homedir == "" {
		errors.New("HOME environment variable isn't set")
	}

	keychains := []string{
		"/System/Library/Keychains/SystemRootCertificates.keychain",
		"/Library/Keychains/System.keychain",
		homedir + "/Library/Keychains/login.keychain",
	}

	for _, v := range keychains {
		cmd := exec.Command("/usr/bin/security", "find-certificate", "-a", "-p", v)
		o, err := cmd.Output()
		if err != nil {
			return err
		}

		c.RootCAs.AppendCertsFromPEM(o)
	}

	return nil
}
