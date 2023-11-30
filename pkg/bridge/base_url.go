package bridge

func (b *Bridge) applyBaseURL() {
	b.BaseAddress.Path = b.BasePath.String()
	b.Server.BaseURL = b.BaseAddress.Get()
}
