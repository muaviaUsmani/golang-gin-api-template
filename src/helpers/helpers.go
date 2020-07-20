package helpers

// HTTPError specifies the error returned with message and http code
type HTTPError struct {
	Code    int
	Message string
	Error   error
}
