// Package atomicio provides race-free, crash-safe file writes for artifacts.
// Pattern: os.CreateTemp(dir, prefix) → write → fsync → close → rename → dir fsync.
// Both helpers refuse to clobber an existing final path (Lstat check).
package atomicio
