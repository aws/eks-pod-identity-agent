package chainrole

import (
	"regexp"

	"github.com/spf13/cobra"
)

var (
	reNamespaceFilter      *regexp.Regexp
	reServiceAccountFilter *regexp.Regexp
)

func AddCMDFlags(cmd *cobra.Command) {
	namespacePattern := cmd.Flags().StringP("chainrole-namespace-pattern", "", "", "Namespace pattern to apply chain role functionality")
	serviceAccountPattern := cmd.Flags().StringP("chainrole-service-account-pattern", "", "", "Service account pattern to apply chain role functionality")

	if namespacePattern != nil && *namespacePattern != "" {
		reNamespaceFilter = regexp.MustCompile(*namespacePattern)
	}

	if serviceAccountPattern != nil && *serviceAccountPattern != "" {
		reServiceAccountFilter = regexp.MustCompile(*serviceAccountPattern)
	}
}
