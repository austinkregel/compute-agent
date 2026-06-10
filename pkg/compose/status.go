package compose

// StackState represents the overall status of a deployed stack.
type StackState struct {
	StackName  string           `json:"stackName"`
	Running    int              `json:"running"`
	Stopped    int              `json:"stopped"`
	Total      int              `json:"total"`
	Containers []ContainerState `json:"containers,omitempty"`
}

// ContainerState describes a single container within a stack.
type ContainerState struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Image   string `json:"image"`
	State   string `json:"state"`
	Status  string `json:"status"`
	Service string `json:"service,omitempty"`
}
