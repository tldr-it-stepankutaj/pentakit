package modules

// Module represents a runnable capability (recon, http enum, nuclei, etc).
type Module interface {
	// Name returns a unique identifier for the module.
	Name() string
	// Description returns a short human-readable description.
	Description() string
}

// Registry stores available modules and allows future discovery.
type Registry struct {
	modules map[string]Module
}

func NewRegistry() *Registry {
	return &Registry{modules: make(map[string]Module)}
}

func (r *Registry) Register(m Module) {
	r.modules[m.Name()] = m
}

func (r *Registry) Get(name string) (Module, bool) {
	m, ok := r.modules[name]
	return m, ok
}

func (r *Registry) All() []Module {
	out := make([]Module, 0, len(r.modules))
	for _, m := range r.modules {
		out = append(out, m)
	}
	return out
}
