package api

//go:generate go tool oapi-codegen -config oapi-codegen.yaml openapi.yaml

import _ "embed"

// Spec is the raw OpenAPI document served to Swagger UI.
//
//go:embed openapi.yaml
var Spec []byte
