/*Package burp parses Burp XML data into a similary formed struct.*/
package burp

import "encoding/xml"

//Issues discovered by Burp
type Issues struct {
	BurpVersion string  `xml:"burpVersion,attr"`
	ExportTime  string  `xml:"exportTime,attr"`
	Issues      []Issue `xml:"issue"`
}

//Issue layed out by Burp
type Issue struct {
	SerialNumber          string            `xml:"serialNumber"`
	Type                  string            `xml:"type"`
	Name                  string            `xml:"name"`
	Host                  Host              `xml:"host"`
	Path                  string            `xml:"path"`
	Location              string            `xml:"location"`
	Severity              string            `xml:"severity"`
	Confidence            string            `xml:"confidence"`
	IssueBackground       string            `xml:"issueBackground"`
	RemediationBackground string            `xml:"remediationBackground"`
	IssueDetail           string            `xml:"issueDetail"`
	IssueDetailItems      []string          `xml:"issueDetailItems>issueDetailItem"`
	RequestResponses      []RequestResponse `xml:"requestresponse"`
}

//Host information
type Host struct {
	Name string `xml:",chardata"`
	IP   string `xml:"ip,attr"`
}

//RequestResponse Given by Host
type RequestResponse struct {
	Response   Response `xml:"response"`
	Request    Request  `xml:"request"`
	Redirected bool     `xml:"responseRedirected"`
}

//Request sent to target
type Request struct {
	Base64 bool   `xml:"base64,attr"`
	Data   string `xml:",chardata"`
	Method string `xml:"method,attr"`
}

//Response by target
type Response struct {
	Base64 bool   `xml:"base64,attr"`
	Data   string `xml:",chardata"`
}

//Parse Burp Data
func Parse(content []byte) (*Issues, error) {
	r := &Issues{}
	err := xml.Unmarshal(content, r)
	if err != nil {
		return r, err
	}
	return r, nil
}
