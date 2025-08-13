package connector

import "html/template"

type C struct {
	ID         string        `json:"id"`
	Name       string        `json:"name"`
	Color      template.CSS  `json:"color"`
	ColorHover template.CSS  `json:"color_hover"`
	IconHTML   template.HTML `json:"icon_html"`
	Config     Config        `json:"config"`
}

type Config struct {
	Issuer       string `json:"issuer"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

func ReadConfig() []C {
	var connectors []C
	if isGoogleConnectorEnabled() {
		connectors = append(connectors, googleConnector())
	}
	if isMicrosoftConnectorEnabled() {
		connectors = append(connectors, microsoftConnector())
	}
	return connectors
}
