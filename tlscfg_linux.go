package tlscfg

import (
	"crypto/tls"
	"errors"
	"io/ioutil"
	"os"
)

func appendSystemCerts(c *tls.Config) error {
	certFiles := []string{
		"/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu/Gentoo etc.
		"/etc/pki/tls/certs/ca-bundle.crt",   // Fedora/RHEL
		"/etc/ssl/ca-bundle.pem",             // OpenSUSE
		"/etc/pki/tls/cacert.pem",            // OpenELEC
	}

	for _, f := range certFiles {
		if _, err := os.Stat(f); os.IsNotExist(err) {
			continue
		}

		ca, err := ioutil.ReadFile(f)
		if err != nil {
			return err
		}

		c.RootCAs.AppendCertsFromPEM(ca)
		return nil
	}

	return errors.New("can't locate system CA certificates")
}
