package store

type InstanceRecord struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Addr        string `json:"addr"`
}
