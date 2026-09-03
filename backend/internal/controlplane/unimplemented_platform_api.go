package controlplane

// unimplementedPlatformAPI owns only Task 1 operations whose product modules
// have not landed yet. Each later module removes its method from this adapter
// when platformAPI gains the real implementation.
type unimplementedPlatformAPI struct{}
