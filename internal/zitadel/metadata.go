package zitadel

// MetadataResults contains paginated metadata query results
type MetadataResults struct {
	Details Details          `json:"details"`
	Result  []MetadataResult `json:"result,omitempty"`
}

// MetadataResult represents a key-value metadata entry
type MetadataResult struct {
	Key   string `json:"key,omitempty"`
	Value string `json:"value,omitempty"`
}
