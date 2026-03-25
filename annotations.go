package authguard

// GuardAnnotation is an Ent schema annotation that declares guards on CRUD operations.
// Guards are strings that name either simple guards (resolved via auth.Resolve) or
// entity guards (rendered as template snippets by the entapi extension).
type GuardAnnotation struct {
	Create []string `json:"create,omitempty"`
	Read   []string `json:"read,omitempty"`
	Update []string `json:"update,omitempty"`
	Delete []string `json:"delete,omitempty"`
	List   []string `json:"list,omitempty"`
}

// Name implements the ent Annotation interface.
func (GuardAnnotation) Name() string { return "AuthGuard" }

// Guards creates a new empty GuardAnnotation builder.
func Guards() *GuardAnnotation { return &GuardAnnotation{} }

func (g *GuardAnnotation) OnCreate(guards ...string) *GuardAnnotation {
	g.Create = guards
	return g
}

func (g *GuardAnnotation) OnRead(guards ...string) *GuardAnnotation {
	g.Read = guards
	return g
}

func (g *GuardAnnotation) OnUpdate(guards ...string) *GuardAnnotation {
	g.Update = guards
	return g
}

func (g *GuardAnnotation) OnDelete(guards ...string) *GuardAnnotation {
	g.Delete = guards
	return g
}

func (g *GuardAnnotation) OnList(guards ...string) *GuardAnnotation {
	g.List = guards
	return g
}
