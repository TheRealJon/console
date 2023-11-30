package bridge

func (b *Bridge) applyBaseURL() {
	b.BaseAddress.Path = b.BasePath.String()
	b.Handler.BaseURL = b.BaseAddress.Get()
}
