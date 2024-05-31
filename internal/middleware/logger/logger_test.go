package logger

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

func TestContextInjection(t *testing.T) {
	var (
		emptyString = ""
		validIp     = "192.168.1.102"
	)

	testCases := []struct {
		name          string
		clientIp      *string
		skipInjection bool
	}{
		{
			name:     "sets the required fields",
			clientIp: &validIp,
		},
		{
			name:     "clientIp is empty",
			clientIp: &emptyString,
		},
		{
			name: "no clientIp specified",
		},
		{
			name:          "can retrieve log even if ctx has not been initialized",
			skipInjection: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			// setup
			logger = logrus.New()
			buffer := bytes.NewBuffer([]byte{})
			logger.Out = buffer
			var ctxLogger *logrus.Entry
			parsedUrl, _ := url.Parse("http://localhost:8080/url")

			if !tc.skipInjection {
				req := &http.Request{
					URL: parsedUrl,
				}

				if tc.clientIp != nil {
					req.RemoteAddr = *tc.clientIp
				}

				InjectLogger(func(writer http.ResponseWriter, request *http.Request) {
					ctxLogger = FromContext(request.Context())
				})(&httptest.ResponseRecorder{}, req)

			} else {
				ctxLogger = FromContext(context.Background())
			}

			// trigger
			ctxLogger.Infof("Any data")

			// verify
			logMessage, err := io.ReadAll(buffer)
			g.Expect(err).To(Not(HaveOccurred()))

			if !tc.skipInjection {
				g.Expect(string(logMessage)).To(ContainSubstring("client-addr"))
			}

			if tc.clientIp != nil && len(*tc.clientIp) != 0 {
				g.Expect(string(logMessage)).To(ContainSubstring(*tc.clientIp))
			}
		})
	}
}
