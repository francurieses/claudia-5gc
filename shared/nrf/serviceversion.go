package nrf

import (
	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/sbi/apiversion"
)

// ServiceVersion builds the NFServiceVersion an NF advertises for svc from the
// shared apiversion table. A nil profile selects the rel17 column.
func ServiceVersion(p *capability.Profile, svc apiversion.Service) NFServiceVersion {
	v := apiversion.Of(p, svc)
	return NFServiceVersion{APIVersionInURI: v.InURI, APIFullVersion: v.Full}
}
