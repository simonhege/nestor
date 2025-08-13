package connector

import "os"

func isMicrosoftConnectorEnabled() bool {
	return os.Getenv("CONNECTOR_MICROSOFT_ISSUER") != "" &&
		os.Getenv("CONNECTOR_MICROSOFT_CLIENT_ID") != "" &&
		os.Getenv("CONNECTOR_MICROSOFT_CLIENT_SECRET") != ""
}

func microsoftConnector() C {
	return C{
		ID:   "microsoft",
		Name: "Microsoft",
		IconHTML: `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-microsoft" viewBox="0 0 16 16">
  <path d="M7.462 0H0v7.19h7.462zM16 0H8.538v7.19H16zM7.462 8.211H0V16h7.462zm8.538 0H8.538V16H16z"/>
</svg>`,
		Color:      "hsl(50, 100%, 40%)",
		ColorHover: "hsl(50, 100%, 25%)",
		Config: Config{
			Issuer:       os.Getenv("CONNECTOR_MICROSOFT_ISSUER"),
			ClientID:     os.Getenv("CONNECTOR_MICROSOFT_CLIENT_ID"),
			ClientSecret: os.Getenv("CONNECTOR_MICROSOFT_CLIENT_SECRET"),
		},
	}
}
