package sources

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

// ErrMemoryNotApproved is returned when memory acquisition is attempted
// without explicit user approval.
var ErrMemoryNotApproved = errors.New("memory acquisition requires explicit approval")

// ErrToolNotFound is returned when the memory acquisition tool (winpmem) is
// not found in the expected tools directory.
var ErrToolNotFound = errors.New("memory acquisition tool not found")

// CollectMemory acquires a full physical memory dump using winpmem (or a
// compatible tool) located in the tools/ directory.
//
// This is a privileged operation that requires:
//  1. Explicit approval (approved must be true).
//  2. Administrator privileges at runtime.
//  3. The winpmem tool to be present in the project's tools/ directory.
//
// outputPath specifies where the memory image should be written.
func CollectMemory(outputPath string, approved bool) error {
	if !approved {
		return ErrMemoryNotApproved
	}

	log.Printf("[memory] WARNING: memory acquisition is a privileged operation")
	log.Printf("[memory] target output: %s", outputPath)

	toolPath, err := findMemoryTool()
	if err != nil {
		return err
	}

	log.Printf("[memory] using tool: %s", toolPath)

	// Ensure the output directory exists.
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	// Run winpmem. The standard invocation is: winpmem.exe <output_file>
	out, err := runCommand(toolPath, outputPath)
	if err != nil {
		return fmt.Errorf("memory acquisition failed: %w\nOutput: %s", err, out)
	}

	// Verify the dump was created.
	info, err := os.Stat(outputPath)
	if err != nil {
		return fmt.Errorf("memory dump not found after acquisition: %w", err)
	}
	log.Printf("[memory] acquired %d bytes", info.Size())

	return nil
}

// findMemoryTool searches for a winpmem executable in the tools/ directory
// relative to the working directory and the executable's directory.
func findMemoryTool() (string, error) {
	candidates := []string{
		filepath.Join("tools", "winpmem.exe"),
		filepath.Join("tools", "winpmem_mini_x64.exe"),
	}

	// Also check relative to the executable's location.
	if exePath, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exePath)
		candidates = append(candidates,
			filepath.Join(exeDir, "tools", "winpmem.exe"),
			filepath.Join(exeDir, "tools", "winpmem_mini_x64.exe"),
		)
	}

	for _, p := range candidates {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p, nil
		}
	}

	return "", ErrToolNotFound
}
