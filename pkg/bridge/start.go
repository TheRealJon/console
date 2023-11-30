package bridge

import (
	"flag"

	"k8s.io/klog"
)

// Starts the bridge server
func Start() {
	// Create a new flag set
	fs := flag.NewFlagSet("bridge", flag.ExitOnError)

	// Initialize klog flags
	klog.InitFlags(fs)
	defer klog.Flush()

	// Instantiate bridge, which will parse flags and apply config
	b := NewBridge(fs)

	// Run the server
	b.ListenAndServe()
}
